const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 8081;

app.use(cors({
    origin: ["https://hoyun-church.kro.kr"],
    methods: ["POST", "GET"],
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => res.send("express on vercel"));

const db = mysql.createConnection({
    host: 'bcowgazscvnaucuxrwya-mysql.services.clever-cloud.com',
    user: 'uri6aztvfszmmws5',
    password: 'FsdxYJV9pPpQ1PoH1gJD',
    database: 'bcowgazscvnaucuxrwya',
});

db.connect((err) => {
    if (err) {
        console.error('MySQL Connection Error:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// JWT 검증 미들웨어 함수
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ error: "You are not authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.json({ error: "Invalid token" });
            } else {
                req.user = decoded;
                next();
            }
        });
    }
};

// 회원가입 엔드포인트
app.post('/signup', (req, res) => {
    const sql = "INSERT INTO login (`name`, `email`, `password`) VALUES (?)";

    bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) {
            return res.json("Error hashing password");
        }

        const values = [
            req.body.name,
            req.body.email,
            hash // 해시된 비밀번호 저장
        ];

        db.query(sql, [values], (err, data) => {
            if (err) {
                return res.json("Error");
            }
            return res.json(data);
        });
    });
});

// 로그인 엔드포인트
app.post('/login', (req, res) => {
    const sql = "SELECT * FROM login WHERE `email` = ?";
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.json("Error");
        }
        if (data.length > 0) {
            bcrypt.compare(req.body.password, data[0].password, (err, result) => {
                if (result) {
                    const name = data[0].name;
                    const email = data[0].email; // 이메일 추가
                    const token = jwt.sign({ name, email }, "jwt-secret-key", { expiresIn: '1d' });
                    
                    // 쿠키 설정 시 보안 옵션 추가
                    res.cookie('token', token, {
                        httpOnly: true,
                        secure: true, // HTTPS 환경에서만 전송
                        sameSite: 'Lax',
                    });

                    return res.json("Success");
                } else {
                    return res.json("Fail");
                }
            });
        } else {
            return res.json("Fail");
        }
    });
});

// /mypage 엔드포인트
app.get('/mypage', verifyUser, (req, res) => {
    const user = req.user;
    return res.json({ status: "Success", name: user.name, email: user.email });
});

app.listen(PORT, () => {
    console.log('Listening on port', PORT);
});
