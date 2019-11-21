package de.hpi.ddm.actors;
import akka.actor.AbstractActor;
import akka.actor.Props;

// This serves solely for making an large message path available for any actor additionally to the usual path
// which has quite low frame size limits.
public class LargeMessageForwarder extends AbstractActor {
    public static final String DEFAULT_NAME = "largeMessages";

    public static Props props() {
        return Props.create(LargeMessageForwarder.class);
    }

    @Override
    public AbstractActor.Receive createReceive() {
        return receiveBuilder()
            .matchAny((object) -> getContext().parent().forward(object, getContext()))
            .build();
    }
}