from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]


def user_exist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else:
        return True


def verify_password(username, password):
    if not user_exist(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]["password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def count_tokens(username):
    tokens = users.find({
        "username": username
    })[0]["tokens"]
    return tokens


def response(status, message):
    retJson = {
        "status": status,
        "message": message
    }
    return jsonify(retJson)


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if (user_exist(username)):
            return response(301, "User already registered")

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "username": username,
            "password": hashed_pw,
            "tokens": 6
        })

        return response(200, "You've successfully registered")


class Detect(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not user_exist(username):
            return response(301, "Invalid Username")

        correct_pw = verify_password(username, password)

        if not correct_pw:
            return response(301, "Invalid Password")

        num_tokens = count_tokens(username)

        if num_tokens <= 0:
            return response(303, "Sorry you are out of tokens please refill!")

        # Calculate the edit distance
        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)

        # ratio is a number between 0 and 1 closer to 1 more silimar is
        ratio = text1.similarity(text2)

        retJson = {
            "status": 200,
            "similarity": ratio,
            "message": "Similarity score calculated successfully"
        }

        current_token = count_tokens(username)

        users.update({
            "username": username
        }, {
            "$set": {
                "tokens": current_token - 1
            }
        })

        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        if not user_exist(username):
            return response(301, "Invalid Username")

        # For test purpose only
        correct_pw = "abc123"

        if not password == correct_pw:
            return response(304, "Invalid admin password")

        current_tokens = count_tokens(username)
        users.update({
            "username": username
        }, {
            "$set": {
                "tokens": refill_amount+current_tokens
            }
        })
        return response(200, "Refilled successfully")


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
