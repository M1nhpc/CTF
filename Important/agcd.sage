"""

find agcd

+ N: list of int
+ R: 

"""
def AGCD(x, N, rho): 
    t = len(x)
    M = block_matrix([
        [2^rho, vector(x).row()],
        [zero_vector(t).column(), identity_matrix(t)*N]
    ]).LLL()
    for r in M.rows():
        g = gcd(abs(r[0]), N)
        if 1 < g < N:
            return N//g

def agcd(N: list[int], R):
    n = N[0]
    
    M = block_matrix([
        [matrix([[R]]), column_matrix(N[1:]).T],
        [0, diagonal_matrix([-n]* (len(N) - 1)) ]
    ]).LLL(algorithm='fpLLL:fast')
    
    for i in M:
        q = int(abs(i[0]) // R)
        if gcd(q, n) != 1 and q != 1 and q != 0:
            p = n // gcd(q, n)
            return p
