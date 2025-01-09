from flask import Flask, render_template
from project import elgamal 
from project import dsa

app = Flask(__name__)

def voteEncrypt(p,g,h,ballot):
    r = 0
    c = 0
    encryptedBallot = []

    for i in len(ballot):
        r,c = elgamal.EGA_encrypt(
                p,
                g,
                h,
                byte(ballot[i])
            )
        encryptedBallot.append((r,c))

    return encryptedBallot

def voteSign(p,q,g,privateKey,k,encryptedBallot):
    signedBallot = dsa.DSA_sign(
        p,
        q,
        g,
        privateKey,
        k,
        encryptedBallot
    )

    return signedBallot

def voteElligibility(r,s,p,q,g,publicKey,signedBallot):
    isVerified = dsa.DSA_verify(
        r,
        s,
        p,
        q,
        g,
        publicKey,
        signedBallot
    )

    return isVerified

def ballotsAddition(encryptedBallotList):
    ballotsAdditionResult = [0,0]

    for i in len(encryptedBallotList):
        ballotsAdditionResult[0] = 
            ballotsAdditionResult[0] + encryptedBallotList[i][0]
        ballotsAdditionResult[1] = 
            ballotsAdditionResult[1] + encryptedBallotList[i][1]

    return ballotsAdditionResult

def candidateElected(privateKey,p,g,ballotsAdditionResult):
    candidateElectedEnc = elgamal.EG_decrypt(
        privateKey
        ,p
        ,ballotsAdditionResult[0]
        ,ballotsAdditionResult[1]
    )

    candidateElectedDec = elgamal.bruteLog(g,candidateElectedEnc,p)

    return candidateElectedDec

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/vote", methods=["POST"])
def voteRoute():
    if request.method == 'POST':
        name      = request.form['voter-name']
        surname   = request.form['voter-surname']
        candidate = request.form['candidate']

