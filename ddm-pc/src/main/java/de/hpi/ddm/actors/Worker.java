package de.hpi.ddm.actors;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import de.hpi.ddm.MasterSystem;

import static java.nio.ByteBuffer.wrap;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() throws NoSuchAlgorithmException {
		this.cluster = Cluster.get(this.context().system());
	}

	////////////////////
	// Actor Messages //
	////////////////////

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;

	// TODO: If lookup is O(1) anyways, distinguishing between the two doesn't really make any sense.
	private Set<ByteBuffer> unsolvedHintHashes;
	private Set<ByteBuffer> unsolvedPasswordHashes;

	private MessageDigest digest = MessageDigest.getInstance("SHA-256");

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);

		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(Master.UnsolvedHashesMessage.class, this::handle)
				.match(Master.HintWorkPacketMessage.class, this::handle)
				.match(Master.PasswordWorkPacketMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(Master.PasswordWorkPacketMessage message){
		Set<Character> reducedAlphabet = message.getAlphabet();

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		this.recursivelyCheckCombinationsForSolutions(
				characterList,
				Character.toString(message.getPrefixChar()),
				message.getLength() - 1
		);

		this.sender().tell(new Master.DoneMessage(), this.self());
	}

	private void handle(Master.HintWorkPacketMessage message){
		// We do not change the message as it might just be a passed reference if we're on the Master System.
		Set<Character> reducedAlphabet = new HashSet<Character>(message.getReducedAlphabet());

		// We remove the char from the alphabet on the worker because we don't want to create too many sets on the master
		boolean returnValue = reducedAlphabet.remove(message.getPrefixChar());
		assert(returnValue);

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		// In some really weird cases, this could lead to an inbox spam of the master inbox. I don't think we need to
		// handle that case, though (would only happen if we accidentally find all hashes really quickly)
		this.recursivelyCheckPermutationsForSolutions(
				characterList,
				characterList.length,
				message.getPrefixChar()
		);

		this.sender().tell(new Master.DoneMessage(), this.self());
	}

	//receive the sets of unsolved hashes and save them locally
	//TODO: possible improvement - save them only once per node instead of once per actor
	private void handle(Master.UnsolvedHashesMessage message){
		this.unsolvedHintHashes = new HashSet<>(message.getHintHashes().length);
		for (byte[] hintHash : message.getHintHashes()) {
			this.unsolvedHintHashes.add(wrap(hintHash));
		}

		this.unsolvedPasswordHashes = new HashSet<>(message.getPasswordHashes().length);
		for (byte[] hintHash : message.getPasswordHashes()) {
			this.unsolvedPasswordHashes.add(wrap(hintHash));
		}

		this.sender().tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
	}

	private void handle(CurrentClusterState message) {
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) {
		this.register(message.member());
	}

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;

			this.getContext()
					.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(new Master.RegistrationMessage(), this.self());
		}
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private byte[] hash(String line) {
		// TODO: What does String.valueOf(line) do here? Can we remove it?
		return this.digest.digest(String.valueOf(line).getBytes(StandardCharsets.UTF_8));
	}

	// TODO: Remove - is slow anyway
	public static String hashToString(ByteBuffer hash) {
		StringBuilder stringBuilder = new StringBuilder();

		ByteBuffer copy = hash.duplicate(); // will only duplicate the internally stored position.
		while(copy.hasRemaining()) {
			stringBuilder.append(Integer.toString((copy.get() & 0xff) + 0x100, 16).substring(1));
		}
		return stringBuilder.toString();
	}

	// Check all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void recursivelyCheckPermutationsForSolutions(Character[] chars, int charsSize, char prefix) {
		if (charsSize == 1) {
			StringBuilder sb = new StringBuilder(chars.length + 1);
			sb.append(prefix);
			for (Character c : chars)
				sb.append(c.charValue());

			String raw_hint = sb.toString();
			byte[] hashBytes = hash(raw_hint);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedHintHashes.contains(wrappedHash))
				this.sender().tell(new Master.HintSolvedMessage(hashBytes, raw_hint), this.self());
		}

		for (int i = 0; i < charsSize; i++) {
			this.recursivelyCheckPermutationsForSolutions(chars, charsSize - 1, prefix);

			if (charsSize % 2 == 1) {
				// If size is odd, swap first and last element
				char temp = chars[0];
				chars[0] = chars[charsSize - 1];
				chars[charsSize - 1] = temp;
			} else {
				// If size is even, swap i-th and last element
				char temp = chars[i];
				chars[i] = chars[charsSize - 1];
				chars[charsSize - 1] = temp;
			}
		}
	}

	// Check all combinations of length chars_left_to_add of a character set.
	// https://www.geeksforgeeks.org/print-all-combinations-of-given-length/
	private void recursivelyCheckCombinationsForSolutions(Character[] base_chars, String prefix, int chars_left_to_add) {
		if (chars_left_to_add == 0)
		{
			byte[] hashBytes = hash(prefix);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedPasswordHashes.contains(wrappedHash))
				this.sender().tell(new Master.PasswordSolvedMessage(hashBytes, prefix), this.self());

			return;
		}

		for (Character base_char : base_chars)
		{
			String recursionPrefix = prefix + base_char;
			recursivelyCheckCombinationsForSolutions(base_chars, recursionPrefix, chars_left_to_add - 1);
		}
	}
}