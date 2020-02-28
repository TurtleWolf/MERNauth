# Starting a new [**_`CRUD`_**](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete 'wikipedia.org') project from scratch in [**_`NODE`_**](https://nodejs.org/ 'NodeJS.org') using [**_`Exprress Generator`_**](https://expressjs.com/en/starter/generator.html 'Exprress Generator')

[![mongodb](public/images/MongoDB.png)](https://www.mongodb.com)
[![mailtrap](public/images/mailtrap.png)](https://mailtrap.io)
[![mapquest](public/images/mapquest.png)](https://developer.mapquest.com)
[![mongo compass](public/images/MongoDB.png)](https://www.mongodb.com/products/compass)

[![https://TurtleWolfe.com/](public/favicon.ico 'https://TurtleWolfe.com/')](https://TurtleWolfe.com/ "Google's Homepage")
[![PostMan Collection](public/images/PostManCollection.png 'PostMan Collection')](https://TurtleWolfe.com/ "Google's Homepage")
[![video comign soon/](public/favicon.ico 'video comign soon')](https://TurtleWolfe.com/ "Google's Homepage")

[![ExpressTemplate previous version](public/images/expressTemplate.png 'previous version')](https://stark-spire-40922.herokuapp.com/ "Google's Homepage")

[![nodejs-the-complete-guide/](public/images/NODE.png 'Master Node JS, build REST APIs with Node.js, GraphQL APIs, add Authentication, use MongoDB, SQL & much more! ')](https://www.udemy.com/course/nodejs-the-complete-guide/ "Google's Homepage")
[![nodejs-api-masterclass](public/images/API.png 'Create a real world backend for a bootcamp directory app')](https://www.udemy.com/course/nodejs-api-masterclass/ "Google's Homepage")
[![mern-stack-front-to-back/](public/images/MERN.png 'Build and deploy a social network with Node.js, Express, React, Redux & MongoDB. Fully updated April 2019 ')](https://www.udemy.com/course/mern-stack-front-to-back/ "Google's Homepage")

```bash
 git init

 git add .
 git commit -m "original 31 files"
 git status
 npx express-generator --view=ejs --git .

 git add .
 git commit -m "8 additional files from running express-generator"
 git status

 npm i bcryptjs colors cookie-parser cors dotenv express express-fileupload express-mongo-sanitize express-rate-limit helmet hpp jsonwebtoken mongoose morgan node-geocoder nodemailer slugify xss-clean

 npm init
 npm install
```

## 2. Initizialize a git repo

```bash
git init
```

## 1. create express scaffolding with **`ejs views`**, **`.gitignore`**, and **`app.js`**

```bash
npx express-generator -e --git .
```

```bash
npx: installed 10 in 4.817s
destination is not empty, continue? [y/N] y

   create : public/
   create : public/javascripts/
   create : public/images/
   create : public/stylesheets/
   create : public/stylesheets/style.css
   create : routes/
   create : routes/index.js
   create : routes/users.js
   create : views/
   create : views/error.ejs
   create : views/index.ejs
   create : .gitignore
   create : app.js
   create : package.json
   create : bin/
   create : bin/www

   install dependencies:
     $ npm install

   run the app:
     $ DEBUG=mernatuh-master:* npm start

        new file:   .gitignore
        new file:   package.json
        new file:   public/stylesheets/style.css
        new file:   routes/index.js
        new file:   views/error.ejs
        new file:   views/index.ejs

```

## 2. reject 4 overlapping overwries

```bash
git init
```

## 3. edit the default `package.json` file by Initizializing a NodeJS project

```bash
npm init
```

## 5. Install the **API** _**`dependencies`**_ (by adding them to the **_`package.json`_** file)

```bash
# API Express Mastery
npm i bcryptjs colors cookie-parser cors dotenv express express-fileupload express-mongo-sanitize express-rate-limit helmet hpp jsonwebtoken mongoose morgan node-geocoder nodemailer slugify xss-clean
```

## 4. Install the **MERN** _**`dependencies`**_ (by adding them to the **_`package.json`_** file)

```bash
npm i bcryptjs client config express express-validator gravatar jsonwebtoken mongoose normalize-url request
```

<!-- ```bash
# API Express Mastery
npm i
# bcryptjs
colors
cookie-parser
cors
dotenv
# express
express-fileupload
express-mongo-sanitize
express-rate-limit
helmet
hpp
# jsonwebtoken
# mongoose
morgan
node-geocoder
nodemailer
slugify
xss-clean
``` -->

## 6. Install the _**`developement dependencies`**_ (by adding them to the _**`package.json`**_ file)

```bash
npm i -D nodemon concurrently
```

## 7. add **_`start`_** and **_`dev`_** scripts (in the **`package.json`**)

> _**`package.json`**_

```json
  "scripts": {
    "start": "NODE_ENV=production node ./bin/www",
    "dev": "nodemon ./bin/www",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
```

## Configure `Enviromental Variables`, beginning with **_`Enviroment`_** and **_`Port`_**

## 8. create 2 empty files in _**`config/`**_

```bash
mkdir config
mkdir controllers
mkdir _data
mkdir middleware
mkdir models
mkdir utils

cd config
touch config.env db.js
cd ..
```

> **_`config.env`_**

```js
NODE_ENV = development;
PORT = 5000;
MONGO_URI=<pasteYOURShere>;

GEOCODER_PROVIDER=mapquest
GEOCODER_API_KEY=

FILE_UPLOAD_PATH= ./public/uploads
MAX_FILE_UPLOAD=1000000

JWT_SECRET=
JWT_EXPIRE=30d
JWT_COOKIE_EXPIRE=30

SMTP_HOST=smtp.mailtrap.io
SMTP_PORT=2525
SMTP_EMAIL=
SMTP_PASSWORD=
FROM_EMAIL=
FROM_NAME=
```

## 9. load enviremental variables from the **_`.env`_** file and additional edits to the **_`app.js`_** file

> **_`app.js`_**

```js
const colors = require('colors');
const dotenv = require('dotenv');

//Load env vars
dotenv.config({ path: './config/config.env' });

const connectDB = require('./config/db');
//  Connect to the database
connectDB();

//Router Files
const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const authRouter = require('./routes/auth');
const widgetsRouter = require('./routes/widgets');

const app = express();
console.log(
  `Server listening in ${process.env.NODE_ENV} on port ${process.env.PORT}!`
    .yellow.bold
);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Dev logging middle-ware
if (process.env.NODE_ENV === 'development') {
  app.use(logger('dev'));
}
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// App Mount Routers
app.use('/', indexRouter);
app.use('/api/v1/users', usersRouter);
app.use('/api/v1/auth', authRouter);
// app.use('/api/v1/widgets', widgetsRouter);
app.use('/widgets', widgetsRouter);
```

## 10. run it from the command line

```bash
npm run dev
```

## 11. stop it with **CNTRL C**

## 12. update **_`var`_** to **_`constant`_**

> **_`app.js`_**

(`var` to `constant` 10 times)

> **_`bin/www`_**

(`var` to `constant` 9 times)

## optionalally, I've added his **_`rejection handler`_** under **_`server error`_**

> **_`bin/www`_**

```js
//  Handle unhand-led promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.log(`Error: ${err.message}`.red.bold);
  // Close server & exit process
  server.close(() => process.exit(1));
});
```

## 13. push it to **`Git Hub`**

```bash
git commit -m "first commit"
git remote add origin git@github.com:TurtleWolf/MERNauth.git
git push -u origin master
```

---

## 14. Connecting to **_`MongoDB`_** with **_`Mongoose`_**

### in the `db.js` file

> **_`db.js`_**

```js
const mongoose = require('mongoose');

const connectDB = async () => {
  const conn = await mongoose.connect(process.env.MONGO_URI, {
    useCreateIndex: true,
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  console.log(
    `MongoDataBase Connected: ${conn.connection.host}`.cyan.underline.bold
  );
};

module.exports = connectDB;
```

## 15. secure credentials

### add **_`config/config.env`_** to **_`.gitignore`_**

> **_`.gitignore`_**

```bash
# dotenv environment variables file
.env
/config/config.env
```

---

## edit **`routes/users.js`**

```bash
cd routes/
touch auth.js widgets.js posts.js profile.js
cd ..  # (or just exit)
```

> _**`routes/users.js`**_

```js
const express = require('express');
const {
  createUser, //  create
  readUsers, //  reads
  readUser, //  read
  updateUser, //  update
  deleteUser, //  delete
} = require('../controllers/users');

const User = require('../models/Users');

const router = express.Router({ mergeParams: true });

const advancedResults = require('../middleware/advancedResults');
const { protect, authorize } = require('../middleware/auth');

router.use(protect);
router.use(authorize('admin'));

router
  .route('/')
  .post(createUser) //  create
  .get(advancedResults(User), readUsers); //  reads

router
  .route('/:id')
  .get(readUser) //  read
  .put(updateUser) //  update
  .delete(deleteUser); //  delete

module.exports = router;
```

> _**`routes/widgets.js`**_

```js
var express = require('express');
var router = express.Router();

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a widget');
});

module.exports = router;
```

> _**`routes/auth.js`**_

```js
const express = require('express');
const {
  register,
  login,
  logout,
  getMe,
  forgotPassword,
  resetPassword,
  updateDetails,
  updatePassword,
} = require('../controllers/auth');

const router = express.Router();

const { protect } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/me', protect, getMe);
router.put('/updatedetails', protect, updateDetails);
router.put('/updatepassword', protect, updatePassword);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resettoken', resetPassword);

module.exports = router;
```

## 16. create **_`model`_** files

```bash
cd models
touch User.js Widget.js
```

> **_`models/Users.js`_**

```js
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please add a valid email',
    ],
  },
  role: {
    type: String,
    enum: ['user', 'publisher'],
    default: 'user',
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
    minlength: 6,
    select: false,
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Encrypt password using bcrypt
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Sign JWT and return
UserSchema.methods.getSignedJwtToken = function() {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate and hash password token
UserSchema.methods.getResetPasswordToken = function() {
  // Generate token
  const resetToken = crypto.randomBytes(20).toString('hex');

  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

module.exports = mongoose.model('User', UserSchema);
```

## 17. create **_`controller`_** files

```bash
cd controllers
touch auth.js users.js widgets.js
```

> **_`controllers/users.js`_**

```js
const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
const User = require('../models/Users');

// @desc      Create a new user                                 CREATE
// @route     POST /api/v1/auth/users
// @access    Private/Admin
exports.createUser = asyncHandler(async (req, res, next) => {
  const user = await User.create(req.body);

  res.status(201).json({
    success: true,
    data: user,
  });
});

// @desc      Reads all users                                   Reads
// @route     GET /api/v1/auth/users
// @access    Private/Admin
exports.readUsers = asyncHandler(async (req, res, next) => {
  res.status(200).json(res.advancedResults);
});

// @desc      READ a single user                                READ
// @route     GET /api/v1/auth/users/:id
// @access    Private/Admin
exports.readUser = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc      Update a user by their /:Identification number    UPDATE
// @route     PUT /api/v1/auth/users/:id
// @access    Private/Admin
exports.updateUser = asyncHandler(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  res.status(201).json({
    success: true,
    data: user,
  });
});

// @desc      Delete a user by their /:Identification number    DELETE
// @route     DELETE /api/v1/auth/users/:id
// @access    Private/Admin
exports.deleteUser = asyncHandler(async (req, res, next) => {
  await User.findByIdAndDelete(req.params.id);

  res.status(204).json({
    success: true,
    data: {},
  });
});
```

> **_`controllers/auth.js`_**

```js
const crypto = require('crypto');
const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
const sendEmail = require('../utils/sendEmail');
const User = require('../models/User');

// @desc      Register user
// @route     POST /api/v1/auth/register
// @access    Public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Create user
  const user = await User.create({
    name,
    email,
    password,
    role,
  });

  sendTokenResponse(user, 201, res);
});

// @desc      Login user
// @route     POST /api/v1/auth/login
// @access    Public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  // Validate email & password
  if (!email || !password) {
    return next(new ErrorResponse('Please provide an email and password', 400));
  }

  // Check for user
  const user = await User.findOne({ email }).select('+password');

  if (!user) {
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  // Check if password matches
  const isMatch = await user.matchPassword(password);

  if (!isMatch) {
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  sendTokenResponse(user, 200, res);
});

// @desc      Log user out / clear cookie
// @route     GET /api/v1/auth/logout
// @access    Private
exports.logout = asyncHandler(async (req, res, next) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(204).json({
    success: true,
    data: {},
  });
});

// @desc      Get current logged in user
// @route     POST /api/v1/auth/me
// @access    Private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  return res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc      Update user details
// @route     PUT /api/v1/auth/updatedetails
// @access    Private
exports.updateDetails = asyncHandler(async (req, res, next) => {
  const fieldsToUpdate = {
    name: req.body.name,
    email: req.body.email,
  };

  const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
    new: true,
    runValidators: true,
  });

  res.status(201).json({
    success: true,
    data: user,
  });
});

// @desc      Update password
// @route     PUT /api/v1/auth/updatepassword
// @access    Private
exports.updatePassword = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('+password');

  // Check current password
  if (!(await user.matchPassword(req.body.currentPassword))) {
    return next(new ErrorResponse('Password is incorrect', 401));
  }

  user.password = req.body.newPassword;
  await user.save();

  sendTokenResponse(user, 201, res);
});

// @desc      Forgot password
// @route     POST /api/v1/auth/forgotpassword
// @access    Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new ErrorResponse('There is no user with that email', 404));
  }

  // Get reset token
  const resetToken = user.getResetPasswordToken();

  await user.save({ validateBeforeSave: false });

  // Create reset url
  const resetUrl = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/auth/resetpassword/${resetToken}`;

  const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Password reset token',
      message,
    });

    return res.status(200).json({ success: true, data: 'Email sent' });
  } catch (err) {
    console.log(err);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new ErrorResponse('Email could not be sent', 500));
  }
});

// @desc      Reset password
// @route     PUT /api/v1/auth/resetpassword/:resettoken
// @access    Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  // Get hashed token
  const resetPasswordToken = crypto
    .createHash('sha256')
    .update(req.params.resettoken)
    .digest('hex');

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ErrorResponse('Invalid token', 400));
  }

  // Set new password
  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  sendTokenResponse(user, 200, res);
});

// Get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
  // Create token
  const token = user.getSignedJwtToken();

  const options = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }

  res
    .status(statusCode)
    .cookie('token', token, options)
    .json({
      success: true,
      token,
    });
}; // Get token from model, create cookie and send response
```

## 18. create **_`middleware`_** files

```bash
cd middleware
touch async.js advancedResults.js auth.js error.js
```

> **_`middleware/async.js`_**

```js
const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

module.exports = asyncHandler;
```

> **_`middleware/advancedResults.js`_**

```js
const advancedResults = (model, populate) => async (req, res, next) => {
  let query;

  // Copy reqest query
  const reqQuery = { ...req.query };

  // Fields to exclude
  const removeFields = ['select', 'sort', 'page', 'limit'];

  // Loop over removeFields and delete them from reqQuery
  removeFields.forEach(param => delete reqQuery[param]);

  // Create query string
  let queryStr = JSON.stringify(reqQuery);

  // Create operators ($gt, $gte, etc)
  queryStr = queryStr.replace(/\b(gt|gte|lt|lte|in)\b/g, match => `$${match}`);

  // Finding Resource
  query = model.find(JSON.parse(queryStr)).populate('courses');

  // Select Fields
  if (req.query.select) {
    const fields = req.query.select.split(',').join(' ');
    query = query.select(fields);
  }

  // Sort
  if (req.query.sort) {
    const sortBy = req.query.sort.split(',').join(' ');
    query = query.sort(sortBy);
  } else {
    query = query.sort('-createdAt');
  }

  // Pagination
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 25;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const total = await model.countDocuments();

  query = query.skip(startIndex).limit(limit);

  if (populate) {
    query = query.populate(populate);
  }

  // Executing Query
  const results = await query;

  // Pagination result
  const pagination = {};

  if (endIndex < total) {
    pagination.next = {
      page: page + 1,
      limit,
    };
  }

  if (startIndex > 0) {
    pagination.prev = {
      page: page - 1,
      limit,
    };
  }
  res.advancedResults = {
    success: true,
    count: results.length,
    pagination,
    data: results,
  };
  next();
};

module.exports = advancedResults;
```

> **_`middleware/async.js`_**

```js
const jwt = require('jsonwebtoken');
const asyncHandler = require('./async');
const ErrorResponse = require('../utils/errorResponse');
const User = require('../models/User');

// Protect routes
exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    // split token from Bearer in header
    token = req.headers.authorization.split(' ')[1];
  }
  // // OR Set token from cookie
  // else if (req.cookies.token) {
  //     token = req.cookies.token;
  // }

  // Make sure token exists
  if (!token) {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded);
    req.user = await User.findById(decoded.id);

    next();
  } catch (err) {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }
});

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorResponse(
          `user ROLE ${req.user.role} is not authorized to access this route`,
          403
        )
      );
    }
    next();
  };
};
```

> **_`middleware/async.js`_**

```js
const ErrorResponse = require('../utils/errorResponse');
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log to console for dev
  console.log(err.stack.red);

  // Mongoose bad ObjectID
  // console.log(err.name);
  if (err.name === 'CastError') {
    const message = `Resource not found; Mongoose bad ObjectID`;
    error = new ErrorResponse(message, 404);
  }

  // Mongoose duplicate key
  // console.log(err.code);
  if (err.code === 11000) {
    const message =
      error.message ||
      `Resource with an id of ${err.value} or ${req.params.id} is not unique`;
    error = new ErrorResponse(message, 400);
  }

  // Mongoose validation error
  // console.log(err.name);
  if (err.name === 'ValidationError') {
    const message =
      Object.values(err.errors).map(val => val.message) ||
      `Resource with an id of ${err.value} or ${req.params.id} Validation ErrorJS MIDDLEWARE`;
    error = new ErrorResponse(message, 400);
  }

  res.status(error.statusCode || 500).json({
    success: false,
    // msg: `ErrorJS MIDDLEWARE:: ${req.params.id} is an odd request..`,
    error: error.message || 'Server Error',
    // data: bootCamp,
  });
};

module.exports = errorHandler;
```

## 19. create **_`utility`_** files

```bash
cd utils
touch errorResponse.js geocoder.js sendEmail.js
```

> **_`utils/errorResponse.js`_**

```js
class ErrorResponse extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
  }
}

module.exports = ErrorResponse;
```

> **_`utils/geocoder.js`_**

```js
const NodeGeoCoder = require('node-geocoder');

const options = {
  provider: process.env.GEOCODER_PROVIDER,

  // Optional depending on the providers
  httpAdapter: 'https', // Default
  apiKey: process.env.GEOCODER_API_KEY, // for Mapquest, OpenCage, Google Premier
  formatter: null, // 'gpx', 'string', ...
};

const geocoder = NodeGeoCoder(options);

module.exports = geocoder;
```

> **_`utils/sendMail.js`_**

```js
const nodemailer = require('nodemailer');

const sendEmail = async options => {
  // create reusable transporter object using the default SMTP transport
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_EMAIL, // user
      pass: process.env.SMTP_PASSWORD, // password
    },
  });

  const message = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`, // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    text: options.message, // plain text body
    // html: "<b>${options.message}</b>" // html body
  };

  // send mail with defined transport object
  const info = await transporter.sendMail(message);

  console.log('Message sent: %s', info.messageId);
};

module.exports = sendEmail;
```

---

## 20. import default user data in the **_`seeder.js`_** file

```bash
touch seeder.js
```

> **_`seeder.js`_**

```js
const fs = require('fs');
const mongoose = require('mongoose');
const colors = require('colors');
const dotenv = require('dotenv');

// Load env vars
dotenv.config({ path: './config/config.env' });

// Load models
// const BootCamp = require('./models/BootCamp');
// const Course = require('./models/Course');
const User = require('./models/User');

// Connect to DB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useFindAndModify: false,
  useUnifiedTopology: true,
});

// Read JSON files

const users = JSON.parse(
  fs.readFileSync(`${__dirname}/_data/users.json`, 'utf-8')
);

// Import data into DB

const importData = async () => {
  try {
    // await BootCamp.create(bootcamps);
    // await Course.create(courses);
    await User.create(users);
    console.log('Data Imported...'.green.inverse);
    process.exit();
  } catch (err) {
    console.error(err);
  }
}; // Import data into DB

// Delete data out of DB
const deleteData = async () => {
  try {
    // await BootCamp.deleteMany();
    // await Course.deleteMany();
    await User.deleteMany();
    console.log('Data Destroyed...'.red.inverse);
    process.exit();
  } catch (err) {
    console.error(err);
  }
}; // Delete data out of DB

if (process.argv[2] === '-i') {
  importData();
} else if (process.argv[2] === '-d') {
  deleteData();
}
```

## 21. edit data set in **_`_data/users.json`_** file to include the users

> **_`_data/users.json`_**

```js
[
  {
    _id: '5c8a1d5b0190b214360dc038',
    name: 'MOE',
    email: 'Moe@gmail.com',
    role: 'user',
    password: '123456',
  },
  {
    _id: '5c8a1d5b0190b214360dc039',
    name: 'Larry',
    email: 'Larry@gmail.com',
    role: 'publisher',
    password: '123456',
  },
  {
    _id: '5c8a1d5b0190b214360dc040',
    name: 'Curly',
    email: 'Curly@gmail.com',
    role: 'admin',
    password: '123456',
  },
];
```

## 22. lvl2heading **_`.env`_** file

> **_`app.js`_**

```js
code;
```

---

## 21. lvl2heading **_`.env`_** file

> **_`app.js`_**

```js
code;
```

## 23. lvl2heading **_`.env`_** file

> **_`app.js`_**

```js
code;
```

## 24. lvl2heading **_`.env`_** file

> **_`app.js`_**

```js
code;
```

---

---

---

---

---

---

---

---

(then I addded a copy of Brad's notes at the bottom of the README.md)

---

## DevConnector 2.0 (then I addded a copy of Brad's notes at the bottom of the README.md)

> Social network for developers

This is a MERN stack application from the "MERN Stack Front To Back" course on [Udemy](https://www.udemy.com/mern-stack-front-to-back/?couponCode=TRAVERSYMEDIA). It is a small social network app that includes authentication, profiles and forum posts.

## Updates since course published

Since the course was published, GitHub has [depreciated authentication via URL query parameters](https://developer.github.com/changes/2019-11-05-deprecated-passwords-and-authorizations-api/#authenticating-using-query-parameters)
You can get an access token by following [these instructions](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line)
For this app we don't need to add any permissions so don't select any in the _scopes_.
**DO NOT SHARE ANY TOKENS THAT HAVE PERMISSIONS**
This would leave your account or repositories vulnerable, depending on permissions set.

It would also be worth adding your `default.json` config file to `.gitignore`
If git has been previously tracking your `default.json` file then...

```bash
git rm --cached config/default.json
```

Then add your token to the config file and confirm that the file is untracked with `git status` before pushing to GitHub.
You'll also need to change the options object in `routes/api/profile.js` where we make the request to the GitHub API to...

```js
const options = {
  uri: encodeURI(
    `https://api.github.com/users/${req.params.username}/repos?per_page=5&sort=created:asc`
  ),
  method: 'GET',
  headers: {
    'user-agent': 'node.js',
    Authorization: `token ${config.get('githubToken')}`,
  },
};
```

## Quick Start

### Add a default.json file in config folder with the folowing

```json
{
  "mongoURI": "<your_mongoDB_Atlas_uri_with_credentials>",
  "jwtSecret": "secret",
  "githubToken": ""
}
```

### Install server dependencies

```bash
npm install
```

### Install client dependencies

```bash
cd client
npm install
```

### Run both Express & React from root

```bash
npm run dev
```

### Build for production

```bash
cd client
npm run build
```

## App Info

### Author

Brad Traversy
[Traversy Media](http://www.traversymedia.com)

### Version

2.0.0

### License

This project is licensed under the MIT License
