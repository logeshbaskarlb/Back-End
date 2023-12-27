import express from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import * as dotenv from "dotenv";
dotenv.config();
import { MongoClient } from "mongodb";
import jsonwebtoken from "jsonwebtoken";
import nodemailer from "nodemailer";

const secretKey = process.env.JWT_SECRET;

const app = express();
const URL = process.env.DB;
const PORT = process.env.PORT;
app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);


app.get("/",(req,res)=>{
  res.json(`Heloo to the server`)
})

app.post("/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    const connection = await MongoClient.connect(URL);
    console.log(connection);
    const db = connection.db("users");
    const newUser = {
      firstName,
      lastName,
      email,
      password: hashedPassword,
    };
    const result = await db.collection("Registered").insertOne(newUser);
    const token = jsonwebtoken.sign(
      {
        userId: result.insertedId,
      },
      secretKey,
      { expiresIn: "1h" }
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
      res.status(404).json({ message: "User or password does not match" });
    } else {
      const passwordValid = await bcrypt.compare(password, user.password);
      if (!passwordValid) {
        res.status(404).json({ message: "User or password does not match" });
      } else {
        const token = jsonwebtoken.sign({ userId: user._id }, secretKey, {
          expiresIn: "1h",
        });
        res.status(200).json({ message: "Login successful", token });
      }
    }
    connection.close();
  } catch (error) {
    console.log(error);
  }
});

app.post("/forget-password", async (req, res) => {
  try {
    const { email } = req.body;
    const connection = await MongoClient.connect(URL);
    const db = connection.db("users");
    const user = await db.collection("Registered").findOne({ email });

    if (!user) {
      res.status(404).json({ message: "User not registered" });
    }

    const token = jsonwebtoken.sign({ id: user._id }, secretKey, 
      {
      expiresIn: "1hr",
    });

    await db.collection("Registered").updateOne(
      { email },
      {
        $set: { token },
      }
    );

    connection.close();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_ID,
        pass: process.env.MAIL_PASSWORD,
      },
    });
    const info = await transporter.sendMail({
      from: process.env.MAIL_ID,
      to: email,
      subject: "Reset password link",
      text: `Click the following link to reset your password: ${process.env.CILENT_URL}/reset-password/${token}`,
    });

    res.status(200).json({ message: "Password reset link sent successfully." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Failed to send password reset email." });
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
          res.send({ message: "Password changed succesfully", user });
        }
      } catch (error) {
        console.log(error);
      }
    });
  } catch (error) {
    console.log(error);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});

// 4000
// Jker79ql0Lhw3ppZ
