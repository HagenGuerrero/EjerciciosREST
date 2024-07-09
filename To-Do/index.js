const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

const app = express();
const port = 8080;
const jwtSecret = "your jwt secret";

app.use(bodyParser.json());
app.use(cors({ origin: 'http://localhost:3000' }));

//relacionado al usuario

app.post("/register", async (req, res) =>{
    const { name, email, pss } = req.body;
    const hashedPss = await bcrypt.hash(pss,8);

    db.query(
        "INSERT INTO user (username, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPss],
        (err, result) =>{
            if(err){
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: "User registered succesfully" });
        }
    );
});

app.post("/login", async (req, res) =>{
    const { email, pss } = req.body;
    db.query(
        "SELECT * FROM user WHERE email = ?",
        [email],
        async(err, results) => {
            if(err){
                return res.status(500).json({ error: err.message });
            }
            if(results.length === 0){
                return res.status(400).json({ message: "User not found" });
            }
            const user = results[0];
            const isPasswordValid = await bcrypt.compare(pss,user.password);

            if(!isPasswordValid){
                return res.status(400).json({ message: "Invalid password" });
            }

            const token = jwt.sign({id: user.user_id}, jwtSecret, {expiresIn: "1h"});

            console.log(jwt.decode(token));
            res.json(token);
        }
    );
});

//relacionada a las tareas

app.post("/new-task", async (req, res) => {
    const { title, description, due_date, reminder } = req.body;
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.decode(token);

    db.query(
        "INSERT INTO task (user_id, tasktitle, taskdescription, deadline, completed, reminder, createdat) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [decoded.id, title, description, Date.parse(due_date), 0, reminder, Date.now()],
        async (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: "Task created succesfully" });
        }
    )
})

app.listen(port,() =>{
    console.log(`Server is running on port ${port}`);
});