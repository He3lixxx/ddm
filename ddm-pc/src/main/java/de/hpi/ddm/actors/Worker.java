package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
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
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class PasswordWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 4661499214826867244L;
		private Set<Character> reducedAlphabet;
		private int length;
		// TODO später: char startChar;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class PasswordSolvedMessage implements Serializable {
		private static final long serialVersionUID = 5219945881030570315L;
		private byte[] hash;
		private String password;
	}

	@Data
	private static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 2476247634500726940L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class HintWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 1147004165303224462L;
		private Set<Character> alphabet;
		private char missingChar;
		// TODO Später: char startChar; // für die Permutation
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class UnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
		private Set<byte[]> hintHashes;
		private Set<byte[]> passwordHashes;
	}

	@Data
	public static class UnsolvedHashesReceivedMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class HintSolvedMessage implements Serializable {
		private static final long serialVersionUID = 3443862827428452603L;
		private byte[] hash;
		private String hint;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;

	private Set<byte[]> unsolvedHintHashes;
	private Set<byte[]> unsolvedPasswordHashes;

	private char hintChar;
	private Set<Character> alphabet;

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
				.match(UnsolvedHashesMessage.class, this::handle)
				.match(HintWorkPacketMessage.class, this::handle)
				.match(PasswordWorkPacketMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(PasswordWorkPacketMessage message){
		//TODO
		//Schleife die alle Kombinationen des Grundalphabets probiert und hashed
		//if match in this.unsolvedPasswordHashes
		//this.sender().tell(new PasswordSolvedMessage)
	}

	private void handle(HintWorkPacketMessage message){
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
	//TODO: possible improvement - save them only once per node instead of once per actor
	private void handle(UnsolvedHashesMessage message){
		this.unsolvedHintHashes = message.hintHashes;
		this.unsolvedPasswordHashes = message.passwordHashes;

		//let the master know that you got the data
		this.sender().tell(new UnsolvedHashesReceivedMessage(), this.self());
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

	private String hash(String line) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashedBytes = digest.digest(String.valueOf(line).getBytes("UTF-8"));

			StringBuffer stringBuffer = new StringBuffer();
			for (int i = 0; i < hashedBytes.length; i++) {
				stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			return stringBuffer.toString();
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
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