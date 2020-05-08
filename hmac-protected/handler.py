import os, hmac, hashlib

def validateHMAC(message, secret, hash):

    # Github and the sign flag prefix the hash with "sha1="
    receivedHash = getHash(hash)

    # hash message with secret
    expectedHMAC = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    createdHash = expectedHMAC.hexdigest()

    return receivedHash == createdHash

def getHash(hash):
    if "sha1=" in hash:
        hash=hash[5:]
    return hash

def handle(req):
    """handle a request to the function
    Args:
        req (str): request body
    """
    messageMAC = os.getenv("Http_Hmac")

    with open("/var/openfaas/secrets/payload-secret", "r") as secretContent:
        payloadSecret = secretContent.read()

    if validateHMAC(req, payloadSecret, messageMAC):
        return "Successfully validated: " + req
    return "HMAC validation failed."

    return req
