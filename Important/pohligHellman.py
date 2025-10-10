def pohligHellmanPGH(p,g,h):
    G=GF(p)(g)
    H=GF(p)(h)
    N=[x for x in factor(p-1, limit = 1 << 26)[:-1]]
    X=[]
    ts = []
    for q, e in tqdm(N):
        f = q ** e
        t = int(p - 1) // int(f)
        dlog = discrete_log(H**t, G**t, ord = f)
        X.append(dlog)
        ts.append(f)

    return crt(X, ts)
