def get_smooth_prime(bits):
    smooth_p = 0
    while not is_prime(smooth_p + 1):
        smooth_p = 2
        while smooth_p.bit_length() < bits:
            prime = getPrime(20)
            smooth_p *= prime
            
    return smooth_p + 1
