# Project idea

There is an inherent security threat in the way IM applications work, from
WhatsApp to Signal. All of them send our messages from our devices to a servers
that we don't own and that we can't inspect, and then to the (devices of the)
people that we wanted to send the message to. Some of these apps claim E2EE via
the "trust me bro" method, others try to prove it by using a very complex
encryption schemas that are... well... hard to verify.

Some of these apps have had several encounters with the laws of some countries
that were demanding access to chat history. We won't go into details about this
in this document. If you care about this sort of stuff and you're reading this,
you already know the story.

This project tries to implement another type of encryption for IM applications.
One that can't be broken. Not by laws, not by master (de)cryption keys, not by
anything. And at the same, it attempts to do so while being simple enough so
that anybody with minimum knowledge in networking and encryption can comprehend
how does it work.

Say hi to "OTR" (Off The Record) in 4 easy steps!

1. You (and the person you want to send messages to) install this app.
2. You start an OTR conversation by typing a question to which both you and
the other person know the answer (eg. "Where did we met for the first time?").
3. Encriptón asks you to provide the answer to that question and then it send a
challenge to the other person. (the provided password never leaves your device)
4. If the other person provides the same password (thus passing the challenge),
the password is used to encrypt all sent and received messages.

The best part is that Encriptón doesn't need any own servers to work, because
the messages are sent to your IM's servers (WhatsApp, Signal, etc...), but they
are encrypted. The servers are acting as data passtrough pipelines as they can't
see any of the content.

No law can make Encriptón provide any encryption keys because there are no keys.
No law can seize control of Encriptón's servers because there are no servers.

This is what you wanted. Enjoy!