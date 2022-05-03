

def to_crt(a, crt_base):
    res = []
    for e in crt_base:
        res.append(a%e)
    return res

def from_crt(a_base, crt_base):
    M = 1
    res = 0
    for e in crt_base:
        M *= e
    print(M)
    for i in range(len(a_base)):
        Mi = M/crt_base[i]
        (_, yi, _) = xgcd(Mi, crt_base[i])
        res += a_base[i] * Mi * yi
    return res % M

a = 100
crt_base = [17, 19, 23]
a_base = to_crt(a, crt_base)
a_rec = from_crt(a_base, crt_base)

q = 6554484396890773809930967563523245729705921265872317281365359162392183254199
P.<x> = PolynomialRing(Zmod(q))
f1 = P(x^(2^11)+1)
f2 = P(x^(2^12)+1)
f3 = P(x^(2^13)+1)
