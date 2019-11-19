package de.hpi.ddm.actors;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
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

	private Set<byte[]> unsolvedHintHashes;
	private Set<byte[]> unsolvedPasswordHashes;

	private char hintChar;
	private Set<Character> alphabet;

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
		//TODO
		//Schleife die alle Kombinationen des Grundalphabets probiert und hashed
		//if match in this.unsolvedPasswordHashes
		//this.sender().tell(new PasswordSolvedMessage)
	}

	private void handle(Master.HintWorkPacketMessage message){
		this.hintChar = message.missingChar;
		this.alphabet = message.alphabet;

		//TODO
		//Schleife die alle permutationen erzeugt und hashed

		//permutation-und-hash-Logik
		//if match in this.unsolvedHintHashes
		//TODO could lead to an inbox spam of the master inbox -> send all solved hashes in one message (less performance but more resistent)
		//this.sender().tell(new HintSolvedMessage)

		//this.sender().tell(new DoneMessage());

	}

	//receive the sets of unsolved hashes and save them locally
	//TODO: possible improvement - save them only once per node instead of once per actor -- use Akka Distributed Data
	private void handle(Master.UnsolvedHashesMessage message){
		this.unsolvedHintHashes = message.getHintHashes();
		this.unsolvedPasswordHashes = message.getPasswordHashes();

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
		return this.digest.digest(String.valueOf(line).getBytes(StandardCharsets.UTF_8));
	}

	private String hashToString(String line) {
		byte[] hashedBytes = this.hash(line);

		StringBuilder stringBuilder = new StringBuilder();
		for (byte hashedByte : hashedBytes) {
			stringBuilder.append(Integer.toString((hashedByte & 0xff) + 0x100, 16).substring(1));
		}
		return stringBuilder.toString();
	}

	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, int n, List<String> l) {
		// If size is 1, store the obtained permutation
		if (size == 1)
			l.add(new String(a));

		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, n, l);

			// If size is odd, swap first and last element
			if (size % 2 == 1) {
				char temp = a[0];
				a[0] = a[size - 1];
				a[size - 1] = temp;
			}

			// If size is even, swap i-th and last element
			else {
				char temp = a[i];
				a[i] = a[size - 1];
				a[size - 1] = temp;
			}
		}
	}
}