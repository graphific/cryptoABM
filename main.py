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
    #print("* generating key...")
    # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(idd)
    key.add_uid(uid, usage={KeyFlags.Certify, KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA512],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    #print("key:",key)
    #print("fingerprint",key.fingerprint) #shows full key id
    #print("uid",uid)
    #print("string uid/nick",idd)
    return key
'''
def encrypt(text,key):#testenc same priv/pub key
    print("* creating pgp message...")
    msg = PGPMessage.new(text,compression=CompressionAlgorithm.BZ2)
    #print(str(msg),msg.signatures,msg.signers)
    print("* signing pgp message...")
    msg |= key.sign(msg)
    #print(str(msg),msg.signatures,msg.signers) #signers shows only short 64-bit key id
    print("* verifification by privkey ok?",str(key.verify(msg))==str(SignatureVerification()))
    assert(str(key.verify(msg))==str(SignatureVerification()))
    #print("* verifying signed pgp message with pubkey...")
    #print(key.pubkey.verify(msg))
    #print("* verifying signed pgp message with privkey...")
    #print(key.verify(msg))
    print("* encrypting signed pgp message...")
    emsg = key.pubkey.encrypt(msg)#, user=idd)
    #print(str(emsg),emsg.signatures,emsg.signers)
    return str(emsg)

def decrypt(raw,key):
    print("* composing text blob into pgp message...")
    #msg = PGPMessage.new(emsg)
    emsg = pgpy.PGPMessage.from_blob(raw)
    print("* decrypting encrypted pgp message...")
    okmsg = key.decrypt(emsg)
    #print(str(okmsg),okmsg.signatures,okmsg.signers) #signers shows only short 64-bit key id
    print("* verifification by pubkey ok?",str(key.pubkey.verify(okmsg))==str(SignatureVerification()))
    assert(str(key.pubkey.verify(okmsg))==str(SignatureVerification()))
    return(okmsg.message)
'''
class PGPAgent(Agent):
    """ An agent with fixed initial wealth."""
    def __init__(self, unique_id, model):
        super().__init__(unique_id, model)
        self.name = fake.first_name()[:4]
        self.hellokey = createKey(self.name)
        helloserver[self.name] = str(self.hellokey.pubkey)  # ascii armored pubkey
        self.friends = []
        self.currentkey = self.hellokey
        self.PAD="*"+self.name+"* "
        #self.lastkey = self.hellokey

    def sendMsg(self,msg):
        #print(self.PAD+"getting msg...")
        #print(msg)
        #print("* composing text blob into pgp message...")
        # msg = PGPMessage.new(emsg)
        emsg = pgpy.PGPMessage.from_blob(msg)
        #print("* decrypting encrypted pgp message...")
        okmsg = self.currentkey.decrypt(emsg)
        # print(str(okmsg),okmsg.signatures,okmsg.signers) #signers shows only short 64-bit key id
        #print("* verifification by pubkey ok?", str(key.pubkey.verify(okmsg)) == str(SignatureVerification()))
        #assert (str(key.pubkey.verify(okmsg)) == str(SignatureVerification()))
        #print(okmsg.message)
        text,pkey= okmsg.message.split("[KEY]")
        print(self.PAD+"got msg - DECRYPTED: [",text,"] - used pkey ",pkey[100:120])
        self.friends[0] = (self.friends[0][0],pkey)


    def step(self):
        #print("*",self.name,"(",self.unique_id,") *")
        # The agent's step will go here.
        #print(self.unique_id, self.name)
        if len(self.friends) == 0:
            #find friend
            #print([k for k in helloserver.keys()])
            #print([k for k in helloserver.keys()])
            for k in [k for k in helloserver.keys()]:
                if not k == self.name:
                    self.friends.append((k,helloserver[k])) #name,key on a friend basis
                    break
        else:
            #print("current friends:",[k for k,v in self.friends])
            #print("chosen friend:",self.friends[0][0])
            #print("sending message...with key fingerprint ",newkey.fingerprint)
            msg = fake.text()[:25]
            #print("     ",msg)
            newkey = createKey(self.name)
            newkeystr = str(newkey.pubkey)  # ascii armored pubkey
            msg += "[KEY]"+newkeystr
            #print("     ",msg)
            print(self.PAD+"sending msg (key fingerprint ", newkey.fingerprint,")")

            #print("* creating pgp message...")
            msg = PGPMessage.new(msg, compression=CompressionAlgorithm.BZ2)
            # print(str(msg),msg.signatures,msg.signers)
            #print("* signing pgp message...")
            msg |= self.currentkey.sign(msg)
            # print(str(msg),msg.signatures,msg.signers) #signers shows only short 64-bit key id
            #print("* verifification by privkey ok?", str(self.currentkey.verify(msg)) == str(SignatureVerification()))
            #assert (str(self.currentkey.verify(msg)) == str(SignatureVerification()))

            #print("* encrypting signed pgp message...")
            keystr = self.friends[0][1]
            #print(keystr)
            pkey = pgpy.PGPKey()
            pkey.parse(keystr)
            emsg = pkey.encrypt(msg)  # , user=idd)
            # print(str(emsg),emsg.signatures,emsg.signers)
            #return str(emsg)

            #SEND
            allagents[self.friends[0][0]].sendMsg(str(emsg))

            #END
            self.currentkey = newkey

class PGPModel(Model):
    """A model with some number of agents."""
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

    #def sayhello(self):


helloserver = {}
allagents = {}

empty_model = PGPModel(2)
#print(helloserver)
#empty_model.findfriendhello()
for m in empty_model.schedule.agents:
    allagents[m.name] = m

for i in range(10):
    empty_model.step()

