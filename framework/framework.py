import time
import logging
from memory_profiler import memory_usage

class Framework:
    def __init__(self, algo):
        self.algo = algo
        self.message = None
        self.results = {}

    def evaluate_elapsed_time(self, fname, iteration):
        params = {}
        if fname == "gen":
            func = self.algo.key_generation
        elif fname == "enc":
            func = self.algo.encryption
            if not self.message:
                self.message = "computer"
            params["plaintext"] = self.message
        elif fname == "dec":
            func = self.algo.decryption
            params["ciphertext"] = self.ciphertext

        start = time.time()
        for _ in range(iteration):
            ret = func(**params)
        end = time.time()

        if fname == "enc":
            self.ciphertext = ret

        key = "elapsed time for {}".format(fname)
        self.results[key] = (end - start) / iteration
        logging.info("Elapsed time for {} ({} iteration): {} ms".format(fname, iteration, self.results[key] * 1000))

    def evaluate_cpu_time(self, fname, iteration):
        params = {}
        if fname == "gen":
            func = self.algo.key_generation
        elif fname == "enc":
            func = self.algo.encryption
            if not self.message:
                self.message = "computer"
            params["plaintext"] = self.message
        elif fname == "dec":
            func = self.algo.decryption
            params["ciphertext"] = self.ciphertext

        start = time.process_time()
        for _ in range(iteration):
            ret = func(**params)
        end = time.process_time()

        if fname == "enc":
            self.ciphertext = ret

        key = "cpu time for {}".format(fname)
        self.results[key] = (end - start) / iteration
        logging.info("CPU time for {} ({} iteration): {} ms".format(fname, iteration, self.results[key] * 1000))

    def evaluate_memory_usage(self, fname):
        params = {}
        if fname == "gen":
            func = self.algo.key_generation
        elif fname == "enc":
            func = self.algo.encryption
            if not self.message:
                self.message = "computer"
            params["plaintext"] = self.message
        elif fname == "dec":
            func = self.algo.decryption
            params["ciphertext"] = self.ciphertext

        mem_usage = memory_usage(func, (params, ))

        if fname == "enc":
            self.ciphertext = ret

        key = "memory usage for {}".format(fname)
        self.results[key] = max(mem_usage)
        logging.info("Memory usage for {}: {}".format(fname, self.results[key]))

    def set_message(self, message):
        self.message = message

    def get_message(self):
        return self.message

    def get_results(self):
        return self.results
