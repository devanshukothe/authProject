const express = require("express");
const app = express();
const userModel = require("./models/user");
const postModel = require("./models/post");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
// const multerConfig = require("./config/multerConfig");

// Middleware
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

// Multer configuration
 const storage = multer.diskStorage({
   destination: (req, file, cb) => {
     cb(null, "./public/image/uploads");
   },
   filename: (req, file, cb) => {
     crypto.randomBytes(12, (err, bytes) => {
       if (err) return cb(err);
       const filename = bytes.toString("hex") + path.extname(file.originalname);
       cb(null, filename);
     });
   },
 });

 const upload = multer({ storage });

app.get("/profile/upload", (req, res) => {
  res.render("profileupload");
});

 app.post("/upload", isLoggedIn, upload.single("image"), async (req, res) => {
  let user = await userModel.findOne({email: req.user.email});
  user.profilepic = req.file.filename;
  await user.save();
   res.redirect("/profile")
 });

// Routes
app.get("/", (req, res) => res.render("index"));

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email });
    if (!user) return res.status(400).send("User not found");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send("Invalid credentials");

    const token = jwt.sign(
      { email, userid: user._id },
      process.env.JWT_SECRET || "shhhh"
    );
    res.cookie("token", token);
    res.status(200).redirect("/profile");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.post("/register", async (req, res) => {
  try {
    const { email, password, username, name } = req.body;
    const existingUser = await userModel.findOne({ email });
    if (existingUser) return res.status(400).send("User already registered");

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = await userModel.create({
      username,
      email,
      name,
      password: hash,
    });

    const token = jwt.sign(
      { email, userid: user._id },
      process.env.JWT_SECRET || "shhhh"
    );
    res.cookie("token", token);
    res.redirect("/login")
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/login", (req, res) => res.render("login"));

app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    const user = await userModel
      .findOne({ email: req.user.email })
      .populate("posts");
    res.render("profile", { user });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.post("/post", isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findOne({ email: req.user.email });
    const { content } = req.body;
    const post = await postModel.create({ user: user._id, content });
    user.posts.push(post._id);
    await user.save();
    res.redirect("/profile");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/like/:id", isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    const index = post.likes.indexOf(req.user.userid);
    if (index === -1) {
      post.likes.push(req.user.userid);
    } else {
      post.likes.splice(index, 1);
    }
    await post.save();
    res.redirect("/profile");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/edit/:id", isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    res.render("edit", { post });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.post("/update/:id", isLoggedIn, async (req, res) => {
  try {
    await postModel.findByIdAndUpdate(req.params.id, {
      content: req.body.content,
    });
    res.redirect("/profile");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/delete/:id", isLoggedIn, async (req, res) => {
  try {
    await postModel.findByIdAndDelete(req.params.id);
    res.redirect("/profile");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/login");
});

// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect("/login");
  }
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET || "shhhh");
    req.user = data;
    next();
  } catch {
    res.redirect("/login");
  }
}

// Start the server
app.listen(3000, () => console.log("Server is running on port 3000"));
