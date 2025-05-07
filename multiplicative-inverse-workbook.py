from math import floor
from math import sqrt

# Euclid's greatest common divisor algorithm: this is how we can verify
# whether (e,phi) are coprime ... with the gcd(e,phi)=1 condition
def gcd(a, b):

    while b != 0:
        a, b = b, a % b

    return a

# extended Euclid's algorithm to find modular inverse in O(log m) so in linear time
# this is how we can find the d value which is the modular inverse of e in the RSA cryptosystem
def modular_inverse(a, b):

    # of course because gcd(0,b)=b and a*x+b*y=b - so x=0 and y=1
    if a == 0:
        return b, 0, 1

    # so we use the Euclidean algorithm for gcd()
    # b%a is always the smaller number - and 'a' is the smaller integer always in this implementation
    div, x1, y1 = modular_inverse(b % a, a)

    # and we update the parameters for x, y accordingly
    x = y1 - (b // a) * x1
    y = x1

    # we use recursion so this is how we send the result to the previous stack frame
    return div, x, y

inv = modular_inverse(7, 120)[1]
if inv < 0: inv += 120
print(inv)
