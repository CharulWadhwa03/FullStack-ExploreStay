const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const User = require("../models/User");

//Configuration Multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/"); //store uploaded files in upload folder
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });

/* USER REGISTER*/
router.post("/register", upload.single("profileImage"), async (req, res) => {
  try {
    //take all info from form
    const { firstName, lastName, email, password } = req.body;

    //uploaded file is available as req.file
    const profileImage = req.file;

    if (!profileImage) {
      return res.status(400).send("No file uploaded");
    }

    //path to upload profile photo
    const profileImagePath = profileImage.path;

    //check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists!" });
    }

    //has the password
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    //create new user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      profileImagePath,
    });

    //save new user
    await newUser.save();

    //send a successful mesage
    res
    .status(200)
    .json({ message: "User registered successfully!", user: newUser });
    } catch (err) {
    console.log(err);
    res
        .status(500)
        .json({ message: "Registration failed!", error: err.message });
    }
    });

  //User Login
    router.post("/login", async(req,res) => {
      try{
        //take info from form
        const{email,password}= req.body

        //check if user exists
        const user = await User.findOne({ email });
        if (!user) {
          return res.status(409).json({ message: "User doesn't exist!" });
        }

        //compare password with hashed pswrd
        const isMatch= await bcrypt.compare(password,user.password)
        if(!isMatch) {
          return res.status(400).json({message: "Invalid Credentials!!"})
        }

        //generate JWT
        const token= jwt.sign({id: user._id },process.env.JWT_SECRET)
        delete user.password

        res.status(200).json({token,user})

      } catch(err) {
        console.log(err)
        res.status(500).json({error : err.message})
      }
    })
    
    module.exports= router