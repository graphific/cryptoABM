from mesa import Agent, Model
from mesa.time import RandomActivation

#https://pythonhosted.org/PGPy/examples.html
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, SignatureType
from pgpy import PGPMessage, PGPUID, PGPKey

#https://github.com/joke2k/faker
from faker import Factory
fake = Factory.create()

import random

def createKey(idd):
    # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(idd)
    key.add_uid(uid, usage={KeyFlags.Certify, KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA512],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    return key

class Friend():
    def __init__(self, name, my_key, friend_key):
        self.name = name
        self.my_key = my_key
        self.friend_key = friend_key


class PGPAgent(Agent):
    """ An agent with fixed initial wealth."""
    def __init__(self, unique_id, model):
        super().__init__(unique_id, model)
        self.name = fake.first_name()[:4]
        self.hellokey = createKey(self.name)
        helloserver[self.name] = str(self.hellokey.pubkey)  # ascii armored pubkey
        self.friends = [] #stores a friends linked: name, my_priv_key, friends_pub_key
        self.PAD="*"+self.name+"* "

    def sendMsg(self, nick, msg):
        print(self.PAD+"msg from: ",nick)

        #find in friend list
        for f in self.friends:
            if f.name == nick:
                cur_f = f
        print(self.PAD+"found friend in friendlist: ",cur_f.name)
        emsg = pgpy.PGPMessage.from_blob(msg)
        okmsg = cur_f.my_key.decrypt(emsg)
        text,pkey = okmsg.message.split("[KEY]")
        print(self.PAD+"got msg - DECRYPTED: [",text,"] - used pkey ",pkey[100:120])
        #new pkey, so update
        cur_f.friend_key = pkey

    def step(self):
        if len(self.friends) == 0:
            #find friend
            for k in [k for k in helloserver.keys()]:
                if not k == self.name:
                    f = Friend(k,self.hellokey,helloserver[k])
                    self.friends.append(f) #name,unique_priv_key, friends pub key
        else:
            #random pick friend to converse with
            cur_friend = self.friends[random.randint(0,len(self.friends)-1)]

            print(self.PAD+"chosen friend:",cur_friend.name)
            msg = fake.text()[:25]
            #always make a new private key:
            newkey = createKey(self.name)
            newkeystr = str(newkey.pubkey)  # ascii armored pubkey
            msg += "[KEY]"+newkeystr
            #print("     ",msg)
            print(self.PAD+"sending msg (key fingerprint ", newkey.fingerprint,")")

            msg = PGPMessage.new(msg, compression=CompressionAlgorithm.BZ2)
            msg |= cur_friend.my_key.sign(msg)
            keystr = cur_friend.friend_key
            pkey = pgpy.PGPKey()
            pkey.parse(keystr)
            emsg = pkey.encrypt(msg)

            allagents[cur_friend.name].sendMsg(self.name, str(emsg))
            cur_friend.my_key = newkey

class PGPModel(Model):
    def __init__(self, N):
        self.num_agents = N
        self.schedule = RandomActivation(self)
        # Create agents
        for i in range(self.num_agents):
            a = PGPAgent(i, self)
            self.schedule.add(a)

    def step(self):
        '''Advance the model by one step.'''
        self.schedule.step()


helloserver = {}
allagents = {}

empty_model = PGPModel(12)

for m in empty_model.schedule.agents:
    allagents[m.name] = m

for i in range(15):
    empty_model.step()

