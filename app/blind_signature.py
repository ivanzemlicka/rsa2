import app.cmath_rsa as cmath_rsa

def blind(random,e,n, message):
    return (cmath_rsa.Binar_power_mod(random,e,n)*message)%n

def unblind(random,n, signed_message):
    return (cmath_rsa.inverse_mod(random,n)*signed_message)%n