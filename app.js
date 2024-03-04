const express = require('express');
const app = express();
const mongoose = require('mongoose');
const http = require('http');
const socket = require("socket.io");
const bodyParser = require('body-parser');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

const port = process.env.PORT;
const secretKey = process.env.SCRETKEY;
const User = require('./model/usermodal.js');
const Messages = require('./model/messageModel.js');



mongoose.connect(process.env.MONGOLINK, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});



app.use(express.urlencoded({extended: true}));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, Date.now() + ext);
    },
  });
  
const upload = multer({ storage: storage });
  
app.use(cors());

app.use(bodyParser.json());
app.use(express.json()); 
app.use('/uploads', express.static("uploads"));


const server = http.createServer(app);  

const io = socket(server, {
    cors: {
      origin: 'https://chatfrontend-2vy4o0rvv-manshu777s-projects.vercel.app', // Replace with your frontend's origin
      methods: ['GET', 'POST'],
      credentials: true,
    },
  });
  

app.post('/signup', upload.single('profileImage'), async (req, res) => {
    try {
      const { username, email, password } = req.body;
  
      const profileImage = req.file.filename;
    
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const newUser = new User({ username, email, password: hashedPassword,  profileImage });
      await newUser.save();
      const token = jwt.sign({ userId: newUser._id }, secretKey, { expiresIn: '1h' });
  
      res.status(201).json({ message: 'User created successfully', token ,newUser});
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  const authenticateUser = (req, res, next) => {
    const authorizationHeader = req.headers['authorization'];
    
    if (!authorizationHeader) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    const token = authorizationHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    try {
      const decoded = jwt.verify(token, secretKey);
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  };
  app.get('/users', authenticateUser, async (req, res) => {
    const userId = req.user.userId;
    const users = await User.find({ _id: { $ne: userId } }, 'username email');
    res.json(users);
  });
  

  global.onlineUsers = new Map();

io.on("connection", (socket) => {
  global.chatSocket = socket;
  
  socket.on("add-user", (userId) => {
    console.log("USERID",userId)
    onlineUsers.set(userId, socket.id);
  });

  socket.on("send-msg", (data) => {
    const sendUserSocket = onlineUsers.get(data.to);
   
    
        console.log(data.messageInput)
      socket.to(sendUserSocket).emit("msg-recieve", data.messageInput);
    
  });
});
  
  app.post('/login', async (req, res, next) => {
    try {
      const { email, password } = req.body;
      
      const user = await User.findOne({ email });
  
      
  
  
      if (!user)
        return res.status(404).json({ msg: 'User not found', status: false });
  
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid)
        return res
          .status(401)
          .json({ msg: 'Incorrect email or password', status: false });
  
      return res.json({ status: true, user });
    } catch (ex) {
      next(ex); // Pass the error to the next middleware
    }
  });
  


  app.get('/alluser/:id', async (req, res,next) => {

    try {
      const users = await User.find({ _id: { $ne: req.params.id } }).select([
        "email",
        "username",
        "profileImage",
        "_id",
      ]);
      return res.json(users);
    } catch (ex) {
      next(ex);
    }
  
  
  })

  app.post('/getmessages', async (req, res,next) => {

    try {
      const { from, to } = req.body;
  
      const messages = await Messages.find({
        users: {
          $all: [from, to],
        },
      }).sort({ updatedAt: 1 });
  
      const projectedMessages = messages.map((msg) => {
        return {
          fromSelf: msg.sender.toString() === from,
          message: msg.message.text,
        };
      });
      res.json(projectedMessages);
    } catch (ex) {
      next(ex);
    }
  
  })
  
  
  
  app.post('/messages', async (req, res,next) => {
  
    try {
      const { from, to, message } = req.body;
      const data = await Messages.create({
        message: { text: message },
        users: [from, to],
        sender: from,
      });
  
      if (data) return res.json({ msg: "Message added successfully." });
      else return res.json({ msg: "Failed to add message to the database" });
    } catch (ex) {
      next(ex);
    }
  
  })
  
 

  server.listen(8000, () => {
    (`Server Connection established on  ${port}`);
 });
 
 
