import elgamal
import dsa

def generateEGKeys(p,g):
    privateKey, publicKey = elgamal.EG_generate_keys(p,g)

    return privateKey, publicKey

def generateSignKeys(app,voterKey,p,q,g):
    privateKey, publicKey, status = dsa.DSA_generate_keys(p,q,g)

    if voterKey not in app.config:
        app.config[voterKey] = [publicKey,0]

    return privateKey    

def ballotEncrypt(p,g,h,ballot):
    r = 0
    c = 0
    encryptedBallot = []

    for i in range(len(ballot)):
        r,c = elgamal.EGA_encrypt(
                p,
                g,
                h,
                ballot[i]
            )
        encryptedBallot.append((r,c))

    return encryptedBallot

def ballotSign(p,q,g,privateKey,k,encryptedBallot):
    vote = [0,0]

    for i in range(len(encryptedBallot)):
        vote[0] = vote[0] + encryptedBallot[i][0]
        vote[1] = vote[1] + encryptedBallot[i][1]
    
    voteInBytes = elgamal.int_to_bytes(vote[0]) + elgamal.int_to_bytes(vote[1])
    r,s,status = dsa.DSA_sign(
        p,
        q,
        g,
        privateKey,
        k,
        voteInBytes
    )

    return r,s

def ballotElligibility(r,s,p,q,g,publicKey,ballot):
    vote = [0,0]

    for i in range(len(ballot)):
        vote[0] = vote[0] + ballot[i][0]
        vote[1] = vote[1] + ballot[i][1]

    voteInBytes = elgamal.int_to_bytes(vote[0]) + elgamal.int_to_bytes(vote[1])
    isVerified = dsa.DSA_verify(
        r,
        s,
        p,
        q,
        g,
        publicKey,
        voteInBytes
    )
 
    return isVerified

def ballotsAddition(destBallot,ballot):
    for i in range(len(ballot)):
        destBallot[i][0] = destBallot[i][0] * ballot[i][0]
        destBallot[i][1] = destBallot[i][1] * ballot[i][1]

def ballotDecrypt(privateKey,p,g,ballotsAdditionResult):
    candidateResultList = []

    for i in range(len(ballotsAdditionResult)):
        candidateElectedEnc = elgamal.EG_decrypt(
            privateKey
            ,p
            ,ballotsAdditionResult[i][0]%p
            ,ballotsAdditionResult[i][1]%p
        )

        candidateResultList.append(elgamal.bruteLog(g,candidateElectedEnc,p))

    return candidateResultList

def choosenBallot(candidate):
    ballot = [0,0,0,0,0]
    ballot[candidate] = 1

    return ballot
