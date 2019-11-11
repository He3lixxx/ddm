package de.hpi.ddm.actors;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";

	public static final int CHUNK_SIZE = 1024;
	
	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class LargeMessage<T> implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private T message;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BytesMessage<T> implements Serializable {
		private static final long serialVersionUID = 4057807743872319842L;
		private T bytes;
		private ActorRef sender;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 5767349179424853159L;
		private ActorRef sender;
		private ActorRef receiver;
	}
	
	/////////////////
	// Actor State //
	/////////////////

	// For each pair (sender, receiver), we need an own byte stream that we write into when we receive chunks of
	// large messages dedicated to go from the sender to the receiver.
	// This is necessary so that multiple senders can simultaneously send messages through the same proxy.
	// First key is the sender, the second key is the receiver.
	private Map<ActorRef, Map<ActorRef, ByteArrayOutputStream>> incomingByteStreams = new HashMap<>();
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	////////////////////
	// Actor Behavior //
	////////////////////
	
	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(LargeMessage.class, this::handle)
				.match(BytesMessage.class, this::handle)
				.match(DoneMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(LargeMessage<?> message) throws IOException {
		ActorRef receiver = message.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));
		
		// Solution using:
		// 1. Serialize the object and send its bytes batch-wise (make sure to use artery's side channel then).
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
		objectStream.writeObject(message.getMessage());

		byte[] bytes = byteStream.toByteArray();

		for(int byte_offset = 0; byte_offset < bytes.length;) {
			byte[] chunk = Arrays.copyOfRange(bytes, byte_offset, byte_offset + CHUNK_SIZE);
			receiverProxy.tell(new BytesMessage<>(chunk, this.sender(), message.getReceiver()), this.self());
			byte_offset += CHUNK_SIZE;
		}

		receiverProxy.tell(new DoneMessage(this.sender(), message.getReceiver()), this.self());
	}

	private void handle(BytesMessage<?> message) {
		Map<ActorRef, ByteArrayOutputStream> receiverMap = incomingByteStreams.get(message.getSender());
		if (receiverMap == null) {
			receiverMap = new HashMap<>();
			incomingByteStreams.put(message.getSender(), receiverMap);
		}

		ByteArrayOutputStream stream = receiverMap.get(message.getReceiver());
		if (stream == null) {
			stream = new ByteArrayOutputStream();
			receiverMap.put(message.getReceiver(), stream);
		}

		byte[] messageBytes = (byte[]) message.getBytes();
		stream.write(messageBytes, 0, messageBytes.length);

		// This will be done until the sender sends us a DoneMessage. At that point, we will deserialize the object
		// from the byte array we collected so far and forward it to the receiver.
	}

	private void handle(DoneMessage message) throws IOException {
		ByteArrayOutputStream stream;
		try {
			stream = incomingByteStreams.get(message.getSender()).get(message.getReceiver());
			if (stream == null)
				throw new NullPointerException();
		} catch (NullPointerException e) {
			this.log().info("Received unexpected DoneMessage: \"{}\"", message.toString());
			return;
		}

		byte[] bytes = stream.toByteArray();
		ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
		ObjectInputStream objectStream = new ObjectInputStream(byteStream);

		try {
			Object object = objectStream.readObject();
			message.getReceiver().tell(object, message.getSender());
		} catch (ClassNotFoundException e) {
			this.log().info("Error while trying to deserialize sent bytes when handling DoneMessage");
		}
	}
}
