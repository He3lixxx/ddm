package de.hpi.ddm.actors;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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

	//defines the size of one message
	public static final int CHUNK_SIZE = 1024*1024;
	//defines the count of messages that are sent in one pull-iteration -> Parameter that can be tuned depending on the system
	public static final int BATCH_SIZE = 10;

	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////

	//All messages are explained above their handling routine

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
		private String uuid;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 5767349179424853159L;
		private ActorRef sender;
		private ActorRef receiver;
		private String uuid;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class WantDataMessage implements Serializable {
		private static final long serialVersionUID = 6123384104453353856L;
		private String uuid;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HaveDataMessage implements Serializable {
		private static final long serialVersionUID = 1167333174474553756L;
		private String uuid;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class MessageContext{
		private ActorRef sender;
		private ActorRef receiver;
		private ByteArrayInputStream data;
	}
	/////////////////
	// Actor State //
	/////////////////

	/*
		Note: UUIDs are Strings to insure serialization

		For each UUID, we need an own byte stream that we write into when we receive chunks of
	 	large messages.
	 	This is necessary so that multiple senders can simultaneously send multiple different
	 	messages through the same proxy and maybe even to the same receiver.
	*/
	private Map<String, ByteArrayOutputStream> incomingByteStreams = new HashMap<>();

	/*
	Map from UUID to MessageContext for the sender.
	Each SenderProxy needs to remember what bytes are left to send for each large message.
	Also the SenderProxy should save the sender/receiver pair once so that the byte messages
	can be sent without them.
	*/
	private Map<String, MessageContext> sendersMemory = new HashMap<>();


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
				.match(HaveDataMessage.class, this::handle)
				.match(WantDataMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}


	/*
	This is the LargeMessage that the Sender wants to send via the LargeMessageProxy. It is sent over the
	large message side channel

	This message type is processed by the SenderProxy.
	 */
	private void handle(LargeMessage<?> message) throws IOException{
		ActorRef receiver = message.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));

		//create the streams for serialization from Object -> Bytes
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);

		//write the message in the ObjectStream which writes it in the ByteStream
		objectStream.writeObject(message.getMessage());

		//Extract the serialized message from the StreamObject as a byte array
		byte[] bytes = byteStream.toByteArray();

		//Each LargeMessage has its own UUID
		String uuid = UUID.randomUUID().toString();

		//create a stream where the message (in bytes) can be read from
		//-> easier way of remembering which bytes have been sent already
		ByteArrayInputStream serializedMessage = new ByteArrayInputStream(bytes);

		//The SenderProxy has to remember the context around the LargeMessage for later
		sendersMemory.put(uuid, new MessageContext(this.sender(), message.getReceiver(), serializedMessage));

		//Initiate the pulling of the ReceiverProxy with a HaveDataMessage
		receiverProxy.tell(new HaveDataMessage(uuid), this.self());
	}

	/*
	The HaveDataMessage is more of a signal that indicates that there is still data left to pull
	from the SenderProxy. That's why the handling of the HaveDataMessage is an immediate response with
	a WantDataMessage from the ReceiverProxy to the SenderProxy.

	Note: If there are many large messages to transfer this "pull" paradigm might also lead to an inbox overflow
	since many large messages would automatically send the HaveDataMessages which automatically trigger the
	WantDataMessages. So one could say it is a lazy pull paradigm. For overflow protection there needs to be a
	mailbox check of some sort before WantDataMessages are sent out.

	This message type is processed by the ReceiverProxy.
	 */
	private void handle(HaveDataMessage message){
		this.sender().tell(new WantDataMessage(message.getUuid()), this.self());
	}

	/*
	The WantDataMessage is a signal that indicates that the ReceiverProxy processed all ByteMessages
	that came in a single batch for the one particular LargeMessage referenced by the UUID. It results in
	the SenderProxy sending another batch of ByteMessages together with a
		- HaveDataMessage if there is still data left
		- DoneMessage if there is no data left
	of the LargeMessage.

	This message type is processed by the SenderProxy.
	 */
	private void handle(WantDataMessage message){
		//get the context corresponding to the message from the ReceiverProxy
		MessageContext context = sendersMemory.get(message.getUuid());
		if (context == null){
			this.log().info("Received unexpected WantDataMessage: \"{}\"", message.toString());
			return;
		}

		//send another batch to the ReceiverProxy
		for(int i = 0; i < BATCH_SIZE; ++i) {
			//important since the message is not always dividable by the CHUNK_SIZE
			int arrayLength = Math.min(context.getData().available(), CHUNK_SIZE);

			//there is still data left to send
			if (arrayLength != 0) {
				//the context includes the stream where data is read from -> read one chunk from it and save it on a variable
				byte[] chunk = new byte[arrayLength];
				int bytesRead = context.getData().read(chunk, 0, arrayLength);
				assert(bytesRead == arrayLength);

				//send the chunk as a ByteMessage to the ReceiverProxy
				this.sender().tell(new BytesMessage<>(chunk, message.getUuid()), this.self());
			} else {
				//since there is no data left the SenderProxy sends a DoneMessage with all the
				//context information from the corresponding LargeMessage so that the ReceiverProxy
				//can de-serialize the message and forward it to the receiver
				this.sender().tell(new DoneMessage(
						context.getSender(), context.getReceiver(), message.getUuid()
				), this.self());
				//remove the entry since this communication is done
				sendersMemory.remove(message.getUuid());
				//returning from this function prevents sending another HaveDataMessage
				return;
			}
		}
		//after sending one batch, immediately send a signal to the ReceiverProxy that more data is available
		//for overflow prevention it is important that these messages are sent in order -> TCP
		this.sender().tell(new HaveDataMessage(message.getUuid()), this.self());
	}

	/*
	The ByteMessages handle the actual payload that is to be sent. Unnecessary information like sender and
	receiver is dropped since this is all handled in other messages.

	This message type is processed by the ReceiverProxy.
	 */
	private void handle(BytesMessage<?> message) {
		//find the stream that is responsible for this large message (UUID)
		ByteArrayOutputStream stream = incomingByteStreams.get(message.getUuid());

		//this is the first message of the large message -> create a new stream and a new mapping entry
		if (stream == null) {
			stream = new ByteArrayOutputStream();
			incomingByteStreams.put(message.getUuid(), stream);
		}

		//write the bytes into the stream
		byte[] messageBytes = (byte[]) message.getBytes();
		stream.write(messageBytes, 0, messageBytes.length);
	}

	/*
	The DoneMessage signals the end of a large message transfer. This means that the object can be
	de-serialized and forwarded to the receiver.

	This message type is processed by the ReceiverProxy.
	 */
	private void handle(DoneMessage message) throws IOException {
		//look up the stream that has the complete information
		ByteArrayOutputStream stream;
		stream = incomingByteStreams.get(message.getUuid());
		if (stream==null){
			this.log().info("Received unexpected DoneMessage: \"{}\"", message.toString());
			return;
		}

		//read the bytes from the stream and de-serialize it to an Object
		byte[] bytes = stream.toByteArray();
		ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
		ObjectInputStream objectStream = new ObjectInputStream(byteStream);
		try {
			//de-serialization
			Object object = objectStream.readObject();
			//forwarding
			message.getReceiver().tell(object, message.getSender());
		} catch (ClassNotFoundException e) {
			this.log().info("Error while trying to deserialize sent bytes when handling DoneMessage");
		}
	}
}
