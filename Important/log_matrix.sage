def log_matrix(g, k, p, r):
    output = []
    g = matrix(Zmod(p ** r), g)
    k = matrix(Zmod(p ** r), k)

    for a_ in g.charpoly().roots(multiplicities = False):
        for b_ in k.charpoly().roots(multiplicities = False):
            try:
                output.append(b_.log(a_))
            except:
                pass
    return output
