import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import random
from enum import Enum
import time
import pickle


class OTState(Enum):
    INIT = 0
    STEP1DONE = 1
    STEP2DONE = 2
    STEP3DONE = 3
    STEP4DONE = 4
    SUCCESS = 5
    FAILED = 6
    EXPIRED = 7


class BaseOTRequest:
    def __init__(self, options, rsa_bits=1024):  # receiver_username,
        # each option in {0,1}^rsa_bits
        self.options = options
        self.private_key = None
        self.randoms = None
        self.state = OTState.INIT  # OTState
        # self.receiver_username = receiver_username
        self.rsa_bits = rsa_bits
        # keep stamp for remove expired ones
        # self.generated_at = time.now()

    def run_step1(self):
        if self.state != OTState.INIT:
            # State is not right
            return False
        rsa_r = Random.new().read
        key = RSA.generate(self.rsa_bits, rsa_r)  # generate pub and priv key
        public_key = key.publickey()  # pub key export for exchange
        self.private_key = key
        max_rand_num = self.private_key.n
        public_key_to_send = pickle.dumps(public_key)
        randoms = []
        for i in range(len(self.options)):
            new_rand = random.randint(0, max_rand_num)
            randoms.append(new_rand)

        self.randoms = randoms
        # NOT sure is safe to transfer rsa random
        self.state = OTState.STEP1DONE
        return {'state': self.state,
                'pickled_public_key': public_key_to_send,
                'rsa_r': rsa_r,  # TODO remove this
                'max_rand_num': max_rand_num,
                'randoms': randoms}

    def run_step3(self, response):
        # TODO add checks
        v = response['v']
        self.state = response['state']

        if self.state != OTState.STEP2DONE:
            # State is not right
            return False

        # decrypt V
        temp = self.private_key.decrypt((v,))
        ks = []

        for rand in self.randoms:
            ks += [self.private_key.unblind(temp, rand)]

        encrypted_options = []
        for option, k in zip(self.options, ks):
            encrypted_options += [option + k]

        self.state = OTState.STEP3DONE
        return {'state': self.state,
                'encrypted_options': encrypted_options}


class BaseOTResponse:

    def __init__(self, selected, rsa_bits=1024):  # sender_username, 
        self.selected = selected
        # self.generated_at = time.now()
        self.state = OTState.STEP1DONE  # OTState
        # self.sender_username = sender_username
        self.rsa_bits = rsa_bits
        # keep stamp for remove expired ones

    def run_step2(self, request):
        # TODO validate input
        self.state = request['state']
        if self.state != OTState.STEP1DONE:
            # State is not right
            return False

        self.public_key = pickle.loads(request['pickled_public_key'])
        randoms = request['randoms']
        num_of_messages = request['max_rand_num']
        rsa_r = request['rsa_r']
        self.random = random.randint(0, num_of_messages)
        (en_k,) = self.public_key.encrypt(self.random, rsa_r) 
        v = self.public_key.blind(en_k, randoms[selected])
        self.state = OTState.STEP2DONE
        return {'v': v,
                'state': self.state
                }

    def run_step4(self, request):
        self.state = request['state']

        if self.state != OTState.STEP3DONE:
            # State is not right
            return False

        result = request['encrypted_options'][self.selected] - self.random

        return result


if __name__ == "__main__":
    options = [12, 13]
    selected = 1  # 0, 1
    a = BaseOTRequest(options)
    b = BaseOTResponse(selected)
    res = a.run_step1()
    res = b.run_step2(res)
    res = a.run_step3(res)
    res = b.run_step4(res)
