from flask import Flask, request, render_template, current_app
from voteFunctions import *

def create_app():
    app = Flask(__name__)
    privateKey, publicKey = generateEGKeys(elgamal.PARAM_P,elgamal.PARAM_G)
    
    with app.app_context():
        current_app.config['ballotConcat'] = [
            [1,1],[1,1],[1,1],[1,1],[1,1]
       ]
        current_app.config['privateKey'] = privateKey
        current_app.config['publicKey'] = publicKey
        current_app.config['counter'] = 0

    return app

app = create_app()

@app.route("/")
def index():
    with app.app_context():
        return render_template(
            'index.html', 
            votes=current_app.config['counter']
        )

@app.route("/generation")
def generationPage():
    return render_template(
        'sign_gen.html'
    )

@app.route("/generate_signature", methods=["POST"])
def generateVoterSignature():
    with app.app_context():
        name = request.form['voter-name']
        surname = request.form['voter-surname']
        id = request.form['voter-id']

        voterKey = f'{name}.{surname}.{id}'
        privateKey = generateSignKeys(
            current_app,
            voterKey,
            dsa.PARAM_P,
            dsa.PARAM_Q,
            dsa.PARAM_G
        )

        return render_template(
            'sign_gen.html',
            privateKey=hex(privateKey)
        )

@app.route("/vote", methods=["POST"])
def voteRoute():
    with app.app_context():
        try:
            current_app.config['counter'] += 1
            if current_app.config['counter'] == 10:
                candidateList = [
                    "Brad Pitt",
                    "George Clown",
                    "François Militaire",
                    "Mike Dyson",
                    "Angelina Sapasse"
                ]
                candidateElected = ballotDecrypt(
                    current_app.config['privateKey'],
                    elgamal.PARAM_P,
                    elgamal.PARAM_G,
                    current_app.config['ballotConcat']
                )
                indexWinner = candidateElected.index(max(candidateElected))

                return render_template(
                    'index.html',
                    candidate=candidateList[indexWinner]
                )

            name      = request.form['voter-name']
            surname   = request.form['voter-surname']
            id        = request.form['voter-id']
            privateKey = int(request.form['voter-pKey'],16)
            candidate = int(request.form['candidate'])
            voterKey = f'{name}.{surname}.{id}'

            if not (name and surname and id and privateKey):
                raise ValueError("Invalid input data")

            if voterKey not in current_app.config:
                current_app.config['counter'] -= 1

                return render_template(
                    'index.html',
                    error="Voter not enregistred !"
                )
            
            if current_app.config[voterKey][1] != 0:
                current_app.config['counter'] -= 1

                return render_template(
                    'index.html',
                    error="Voter was already voted !"
                )

            current_app.config[voterKey][1] = 1
            nonce = dsa.DSA_generate_nonce(dsa.PARAM_Q)
            ballot = choosenBallot(candidate)
            encryptedBallot = ballotEncrypt(
                elgamal.PARAM_P,
                elgamal.PARAM_G,
                current_app.config['publicKey'],
                ballot
            )
            r,s = ballotSign(
                dsa.PARAM_P,
                dsa.PARAM_Q,
                dsa.PARAM_G,
                privateKey,
                nonce[0],
                encryptedBallot
            )
            isVerified = ballotElligibility(
                r,
                s,
                dsa.PARAM_P,
                dsa.PARAM_Q,
                dsa.PARAM_G,
                current_app.config[voterKey][0],
                encryptedBallot
            )

            if isVerified:
                ballotsAddition(current_app.config['ballotConcat'], encryptedBallot)

                return render_template(
                    'index.html',
                    votes=current_app.config['counter'],
                    success='Thanks for your vote !'
                )
            else:
                current_app.config['counter'] -= 1

                return render_template(
                    'index.html',
                    error='Wrong Signature !'
                )
        except Exception as e:
            current_app.logger.error(f'Error in voteRoute: {str(e)}')

if __name__ == "__main__":
    app.run(debug=True)
