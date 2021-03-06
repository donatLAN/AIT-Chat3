from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from base64 import b64encode
from message import Message
import base64
from time import sleep
from threading import Thread
import json
import hashlib

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        self.key_nounce = 0 # holder for the nounce of the setup message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True

        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''
        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...
        
        user_id = self.manager.user_name
        pad_user_id = "{:<8}".format(user_id)
        nounce = Random.new().read(8)
        self.key_nounce = nounce

        msg_raw = base64.encodestring('0' + nounce + pad_user_id)
        self.manager.post_message_to_conversation(msg_raw)

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages

        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''
        buffer_msg = base64.decodestring(msg_raw)
        type_byte = buffer_msg[0]
        
        if type_byte == '0':
            if owner_str == self.manager.user_name:
                return
            self.incoming_setup_message(buffer_msg)

        elif type_byte == '1':
            if owner_str == self.manager.user_name:
                return
            self.incoming_key_exchange(buffer_msg)

        elif type_byte == '2':
            self.incoming_encrypted_message(buffer_msg, msg_id, owner_str)

        else:
            return

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message

        :param msg_raw: raw message
        :return:
        '''

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        # process outgoing message here
		# example is base64 encoding, extend this with any crypto processing of your protocol
        self.outgoing_encrypted_message(msg_raw)

    def outgoing_key_exchange(self, nounce, pad_user_id):
        '''
        Process the outgoing key exchange

        :param nounce: nounce sent in from the setup message
        :param pad_user_id: the padded user id of the sender of setup message
        :return: message to be sent to the server
        '''
        user_id = pad_user_id.strip()

        # get requester's public key
        kfile = open('users/' + user_id + '/public_key.pem')
        keystr = kfile.read()
        kfile.close()
        pubkey = RSA.importKey(keystr)
        cipher = PKCS1_OAEP.new(pubkey)

        # get the symmetric key and publicly encrypt
        symkey = self.get_symmetric_key()
        if symkey == -1:
            return
        pad_current_user = "{:<8}".format(self.manager.user_name)
        data = (pad_current_user + symkey).encode('utf-8')
        pubenc = cipher.encrypt(data)

        # prepare header
        ad = '1' + pad_current_user + nounce
        data_length = str(len(ad + pubenc) + 8).zfill(8)
        header = ad + data_length

        h = SHA.new()
        h.update(header + pubenc)

        # retrieve private key
        kfile = open('users/' + self.manager.user_name + '/private_key.pem')
        keystr = kfile.read()
        kfile.close()
        privkey = RSA.importKey(keystr)

        # sign package
        signer = PKCS1_PSS.new(privkey)
        user_sig = signer.sign(h)

        msg_raw = base64.encodestring(header + pubenc + user_sig)
        self.manager.post_message_to_conversation(msg_raw)

    def outgoing_encrypted_message(self, msg_raw):
        '''
        Encrypting an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''
        key = self.get_symmetric_key()
        if key == -1:
            return

        type_byte = '2'
        pad_user_id = "{:<8}".format(self.manager.user_name)
        seq_num = str(self.get_last_message_id() + 1).zfill(8)
        iv = Random.new().read(8)
        header = type_byte + pad_user_id + seq_num + iv
        ad_length = chr(len(header + msg_raw))
        ad_length = chr(0)*(8 - len(ad_length)) + ad_length

        ctr = Counter.new(128, initial_value=long(iv.encode('hex'),16))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

        cbcmac = self.generate_cbcmac(header + msg_raw, key,
            iv + ad_length)

        encoded_msg = base64.encodestring(header + cipher.encrypt(msg_raw) + cbcmac)
        self.manager.post_message_to_conversation(encoded_msg)

    def incoming_setup_message(self, msg_raw):
        '''
        Process an incoming setup message and passes info to
        the outgoing_key_exchange method

        :param msg_raw: raw message
        :return:
        '''
        nounce = msg_raw[1:9]
        pad_user_id = msg_raw[9:]
        self.outgoing_key_exchange(nounce, pad_user_id)        

    def incoming_key_exchange(self, msg_raw):
        '''
        Process an incoming key exchange to get the symmetric key

        :param msg_raw: raw message
        :return:
        '''
        # process header
        pad_user_id = msg_raw[1:9]
        user_id = pad_user_id.strip()

        nounce = msg_raw[9:17]

        pad_msg_length = msg_raw[17:25]
        msg_length = int(pad_msg_length)

        data = msg_raw[25:msg_length]
        signature = msg_raw[msg_length:]

        # checking nounces for freshness
        if nounce != self.key_nounce:
            return

        h = SHA.new()
        h.update(msg_raw[:msg_length])

        # get public key to verify
        kfile = open('users/' + user_id + '/public_key.pem')
        keystr = kfile.read()
        kfile.close()
        pubkey = RSA.importKey(keystr)
        verifier = PKCS1_PSS.new(pubkey)

        if not verifier.verify(h, signature):
            return

        # retrieve private key
        kfile = open('users/' + self.manager.user_name + '/private_key.pem')
        keystr = kfile.read()
        kfile.close()
        privkey = RSA.importKey(keystr)
        cipher = PKCS1_OAEP.new(privkey)
        
        decrypt_data = cipher.decrypt(data).decode('utf-8')
        symkey = decrypt_data[8:] # ignore user_id

        # write the key in the keychain
        self.manager.write_new_key(self.id, symkey)

    def incoming_encrypted_message(self, buffer_msg, msg_id, owner_str):
        '''
        Process an incoming encrypted message and prints valid messages

        :param buffer_msg: message to be processed
        :param msg_id: ID of the message
        :param owner_str: user_id of the sender
        :return:
        '''
        key = self.get_symmetric_key()
        if key == -1:
            return

        header = buffer_msg[:25]
        pad_user_id = buffer_msg[1:9]
        seq_num = buffer_msg[9:17]
        iv = buffer_msg[17:25]
        data = buffer_msg[25:-AES.block_size]
        cbcmac = buffer_msg[-AES.block_size:]

        # check for replay attacks
        int_seq_num = int(seq_num)
        if msg_id > seq_num:
            return

        ctr = Counter.new(128, initial_value=long(iv.encode('hex'),16))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        decoded_msg = cipher.decrypt(data)

        ad_length = chr(len(header + decoded_msg))
        ad_length = chr(0)*(8 - len(ad_length)) + ad_length

        derived_mac = self.generate_cbcmac(header + decoded_msg, key,
            iv + ad_length)

        if (cbcmac != derived_mac):
            return

        # print message and add it to the list of printed messages
        self.print_message(
            msg_raw=decoded_msg,
            owner_str=owner_str
        )

    def generate_cbcmac(self, msg_raw, key, iv):
        '''
        Helper function for generating a cbcmac

        :param msg_raw: raw message
        :param key: symmetric key for applying the cbcmac
        :param iv: the initial vector for cbcmac
        :return: the cbcmac generated
        '''
        # pad msg if needed, padding sheme is x01 x00 ... x00
        plen = AES.block_size - len(msg_raw)%AES.block_size
        if (plen != AES.block_size):
            msg_raw += chr(1)
            if (plen > 1):
                msg_raw += chr(0)*(plen-1)

        # create AES cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # compute CBC MAC value
        emsg = cipher.encrypt(msg_raw)
        comp_mac = emsg[-AES.block_size:]

        return comp_mac

    def get_symmetric_key(self):
        '''
        Retrives the symmetric key for the conversation from
        the user's keychain file
        :return: the symmetric key for the conversation
        '''
        with open('users/' + self.manager.user_name + '/keychain.txt', "r") as jsonfile:
            try:
                keychain = json.load(jsonfile)
            except ValueError:
                keychain = {}

        # if user does not have key yet
        if keychain.has_key(str(self.id)):
            return keychain[str(self.id)]
        else:
            return -1

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)