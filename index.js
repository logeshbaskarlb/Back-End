const express = require("express")
const bcrypt = require("bcryptjs")
const jsonwebtoken =require("jsonwebtoken")
const cors = require("cors")
const { MongoClient} = require("mongodb");
const dotenv = require("dotenv").config()
const app = express();
const URL = process.env.DB;
const secretKey = process.env.JWT_SECRET;
const PORT = 4000;
const nodemailer = require("nodemailer");


app.use(express.json());
app.use(
  cors({
    origin:'*'
  })
);

app.get("/", (req, res) => {
  res.json(`Heloo to the server`);
});

app.post("/register", async (req, res) => {
  try {       
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const connection = await MongoClient.connect(URL);
    const db = connection.db("users");
    const newUser = {
      name,
      email,
      password: hashedPassword,
    };
    const result = await db.collection("Registered").insertOne(newUser);
    const token = jsonwebtoken.sign(
      {
        userId: result.insertedId,
      },
      secretKey,
      { expiresIn: "24h" }
    );
    res.status(201).json({
      message: " Registration success",
      newUser,
      token,
    });
    connection.close();
  } catch (error) {
    console.log(error);
    
    res.status(500).json({
      message: "Server error",
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const connection = await MongoClient.connect(URL);
    const db = connection.db("users");
    const user = await db.collection("Registered").findOne({
      email,
    });
    if (!user) {
      res.status(404).json({ message: "User or password not match!" });
    } 
      const passwordValid = await bcrypt.compare(password, user.password);
      if (!passwordValid) {
        res.status(404).json({ message: "User or password not match!" });
      }
        const token = jsonwebtoken.sign({ userId: user._id }, secretKey, {
          expiresIn: "24h",
        });
        res.status(200).json({
          userId: user._id,
          token,
        });
        connection.close();
   
  } catch (error) {
    console.log(error);
    
    res.status(500).json({ message: "Internal server error" });
  }
});

//forgot-password
app.post("/forgot-password", async (req, res) => {
    
  try {
    const { email } = req.body;
    const connection = await MongoClient.connect(URL);
    const db = connection.db('users');
    const user = await db.collection('Registered').findOne({ email });

    if(!user){
     res.status(404).json({
      message: "User not register"
     });
    }

    const token = jsonwebtoken.sign({ id: user._id }, secretKey, { expiresIn: '24hr' });

    await db.collection('Registered').updateOne({ email }, {
        $set: { token }
    });

    connection.close();

    const transporter = nodemailer.createTransport({ 
        service: 'gmail',
        auth: {
            user: process.env.MAIL_ID,
            pass: process.env.MAIL_PASSWORD,
        },
    });

    const info = await transporter.sendMail({
        from: process.env.MAIL_ID,
        to: email,
        subject: 'Reset password link',
        html: `Click the following link to reset your password :  ${process.env.CLIENT_URL}/reset-password/${token}`
    });

    console.log(process.env.CLIENT_URL)
   console.log(info);
    res.status(200).json({ message: 'Password reset link sent successfully.' });
} catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Failed to send password reset email.' });
}
});


app.post("/reset-password/:token", async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;
    const token = req.params.token;
    jsonwebtoken.verify(token, secretKey, async (err, decoded) => {
      try {
        if (err) {
          res.json({
            message: "Error with token",
          });
        } else {
          const hashedPassword = await bcrypt.hash(password, 10);
          const connection = await MongoClient.connect(URL);
          const db = connection.db("users");
          const user = await db
            .collection("Registered")
            .findOne({ token: token });
          await db.collection("Registered").updateOne(
            { token },
            {
              $set: {
                password: hashedPassword,
                confirmPassword: hashedPassword,
              },
            }
          );
          connection.close();
          res.status(200).send({ message: "Password changed succesfully", user });
        }
      } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});

// 4000
// Jker79ql0Lhw3ppZ
