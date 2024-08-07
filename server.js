const express = require('express')
const mysql = require('mysql')
const cors = require('cors')
const port = process.env.PORT || 8081

const app = express();

app.use(cors({
    origin: 'https://hoyunchurch.netlify.app/'  // Netlify에서 호스팅되는 프론트엔드 URL
}));

app.use(express.json());

const db = mysql.createConnection({
    host: "process.env.DB_HOST",
    user: "process.env.DB_USER",
    password: "process.env.DB_PASSWORD",
    database: "process.env.DB_NAME",
    port: "process.env.DB_PORT"
})

app.post('/signup', (req, res) => {
    const sql = "INSERT INTO login (`name`, `email`, `password`) VALUES (?)";
    const values = [
        req.body.name,
        req.body.email,
        req.body.password
    ];

    db.query(sql, [values], (err, data) => {
        if (err) {
            return res.json("Error");
        }
        return res.json(data);
    });
});

app.post('/login', (req, res) => {
    const sql = "SELECT * FROM login WHERE `email` = ? AND `password` = ?";
    db.query(sql, [req.body.email, req.body.password], (err, data) => {
        if (err) {
            return res.json("Error");
        }
        if (data.length > 0) {
            return res.json("Success");
        } else {
            return res.json("Fail");
        }
    });
});


app.listen(port, () => {
    console.log(`Listening on ${port}`);
})