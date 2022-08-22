require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const uri = process.env.MONGO_URI;
const yup = require("yup");
const bcrypt = require("bcrypt");
const cors = require('cors')

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors())

const saltRounds = 10;
const client = new MongoClient(uri);

let schema = yup.object().shape({
	email: yup.string().email().required(),
	password: yup.string().required(),
});
let collection;

const connectFunc = async () => {
	try {
		await client.connect();
		collection = client.db().collection("user-details");
		console.log("Connected successfully to server");
	} catch {
		console.dir;
	}
};

app.post("/signup", async (req, res) => {
	try {
		try {
			await schema.validate(req.body);

		} catch (err) {
			throw { statusCode: 421, message: err.message };
        }
        const response = await client
				.db()
				.collection("user-details")
                .findOne({ email: req.body.email });
            if (response) {
                throw { statusCode: 409, message: "User already exists." };
            }
		const hash = bcrypt.hashSync(req.body.password, saltRounds);
		await collection.insertOne({ email: req.body.email, password: hash });
		res.status(201).send("Data insert successfully."); //add createdAt field
	} catch (err) {
		console.error(err);
		res
			.status(err.statusCode || 500)
			.send(err.message || "Internal server error");
	}
});

app.post("/login", async (req, res) => {
	try {
		try {
			await schema.validate(req.body);

		} catch (err) {
			throw { statusCode: 421, message: err.message };
        }
		const result = await client
			.db()
			.collection("user-details")
            .findOne({ email: req.body.email });
            if(result == undefined) {
                throw { statusCode: 404, message: "User does not exist." };
		}
		const response = bcrypt.compareSync(req.body.password, result.password);
        if (response) {
            res.send("Response validated!");    
        } else {
            throw { statusCode: 401, message: "Invalid Password" };
        }
	} catch (err) {
		console.error(err);
		res
			.status(err.statusCode || 500)
			.send(err.message || "Internal server error");
	}
});

connectFunc().then(() => {
	app.listen(process.env.PORT || 3000, async () => {
		console.log("Listening for requests...");
	});
});
