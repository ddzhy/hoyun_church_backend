const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config({ path: '.env.production' });  // 환경 변수 로드

const app = express();
const PORT = process.env.PORT || 8081

// CORS 설정
app.use(cors({
    origin: ["https://hoyun-church.kro.kr"],  // 실제 사용될 프론트엔드 도메인
    methods: ["POST", "GET", "OPTIONS"],      // CORS preflight 요청을 처리하기 위해 OPTIONS 추가
    credentials: true                         // 클라이언트 측 쿠키 사용 허용
}));

app.use(express.json());
app.use(cookieParser());

// 기본 라우트
app.get("/", (req, res) => res.send("express on vercel"));

// MySQL 데이터베이스 설정
const db = mysql.createConnection({
    host: "bcowgazscvnaucuxrwya-mysql.services.clever-cloud.com",
    user: "uri6aztvfszmmws5",
    password: "FsdxYJV9pPpQ1PoH1gJD",
    database: "bcowgazscvnaucuxrwya",
});

// MySQL 연결
db.connect((err) => {
    if (err) {
        console.error('MySQL Connection Error:', err.message);
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
    };
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
            hash
        ];

        db.query(sql, [values], (err, data) => {
            if (err) {
                return res.json("Error");
            }
            return res.json("Signup Successful");
        });
    });
});

app.post('/login', (req, res) => {
    const sql = "SELECT * FROM login WHERE `email` = ?";
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            console.error('Database Error:', err);  // 디버깅: 데이터베이스 오류 로그
            return res.json("Error");
        }
        if (data.length > 0) {
            bcrypt.compare(req.body.password, data[0].password, (err, result) => {
                if (err) {
                    console.error('Bcrypt Error:', err);  // 디버깅: bcrypt 오류 로그
                    return res.json("Error");
                }
                // 로그인 성공 후 쿠키 설정
                if (result) {
                    const name = data[0].name;
                    const email = data[0].email;
                    const token = jwt.sign({ name, email }, "jwt-secret-key", { expiresIn: '1d' });

                    res.cookie('token', token, {
                        httpOnly: true,  // 클라이언트 측 JavaScript에서 쿠키 접근 방지
                        secure: true,    // HTTPS에서만 전송, 로컬 개발 환경에서는 false로 설정
                        sameSite: 'None', // CORS 설정에 맞게 None, Strict, Lax 중 선택
                        maxAge: 24 * 60 * 60 * 1000 // 1일 동안 유효
                    });

                    return res.json("Success");
                }

                 else {
                    return res.json("Fail");  // 실패한 경우
                }
            });
        } else {
            console.log('No user found with email:', req.body.email);  // 디버깅: 사용자 이메일 로그
            return res.json("Fail");  // 수정: 실패 메시지 "Fail"
        }
    });
});

// /mypage 엔드포인트
app.get('/mypage', verifyUser, (req, res) => {
    const user = req.user;
    return res.json({ status: "Success", name: user.name, email: user.email });
});

// 서버 실행
app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});
