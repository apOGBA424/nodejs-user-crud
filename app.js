require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');


// middlewares
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// variables
const port = process.env.PORT || 3000;
const jwtsecret = process.env.JWT_SECRET;


// temporal database
const usersList = []; //On production app, replace with real DB

app.listen(port, ()=>{console.log(`server running on port ${port}`)});




//**************************************
//            ROUTES
//************************************** 


// get all user registered in database
app.get('/users', (req, res)=>{
    console.log('all users');
    console.table(usersList);
    res.json(usersList);
});


// create a new user
app.post('/signup', async(req, res)=>{

    // check if the user is registered already
    const alreadyUser = usersList.find((user)=>user.name === req.body.name);

    if (alreadyUser) {
        return res.status(409).json({'msg': 'User already exists'});
    }

    const user = {
        user_id : new Date().valueOf().toString(),
        name : req.body.name,
        password : await bcrypt.hash(req.body.password, 10),
    }

    usersList.push(user);
    res.status(201).send(user);
});



// login
app.post('/users/login', async(req, res)=>{
    const userAccount = usersList.find((user)=>user.name === req.body.name);
    
    // check if user account exists
    if (userAccount == null) {
        res.status(400).send({'msg':'user not found'});
    }

    try {  
        // compare current password with hasdedPassword
        const isPasswordValid = await bcrypt.compare(req.body.password, userAccount.password);
        if (!isPasswordValid) {
            res.status(400).send({'msg':'password is incorrect'});
        }


        // if password is correct, sign jwt accessToken
        if (isPasswordValid) {
            console.info(`user_id--> ${userAccount.user_id}`)
            console.info(`jwtsecret--> ${jwtsecret}`)
            
            // generate an access accessToken
            const accessToken = jwt.sign({user_id: userAccount}, jwtsecret) //jwtsecret is: 'jwt-secr3t'
            
            console.info('log-in successful')
           
            // store the accessToken in a cookie
            // res.cookie('accessToken', accessToken, {httpOnly: true});
            const cookietoken = res.cookie('accessToken', accessToken, {httpOnly: true});

            res.status(200).json({'msg':`${userAccount.name} log-in successful`,accessToken,jwtsecret});
        }else{
            res.status(400).send({'msg':'log-in failed'})
        }
    } catch (err) {
        res.status(500).json({'msg': err.message});
    }
});


// create auth bearer token middleware
function checkAuthMiddleware(req, res, next) {
    const accessToken = req.header.authorization;

    let isTest = true;
    // let isTest = false;
    if (isTest) {
        console.log('\n\n\nvalid credentials');
        // res.json({'msg':'authorized',usersList,accessToken})
        res.redirect('/users')
    }else{
        res.status(401).json({'msg':'invalid credentials'})
    }

    next();
}


// protected routes only for authorised users
app.get('/user/protected',checkAuthMiddleware ,(req, res)=>{
    // res.json({'msg':'protected-route middleware'});
});



// get one user by id
app.get('/user/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    if(user){
    res.status(200).json({msg: 'user found successfully',user});
    }else{
        res.status(404).send({'msg': 'user not found'});
    }
});


// update user's record (eg: password)
app.put('/user/update/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    if(!user){
        res.status(404).send({'msg': 'user not found'});
    }

    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    user.password = hashedPassword;

    res.status(200).json({msg: 'password updated successfully'});
});


// logout user
app.get('/user/logout/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    console.log(user)
    res.status(204).json({msg: 'log-out successful'});
});


// delete user
app.get('/user/delete/:id', (req, res)=>{
    const userIndex = usersList.findIndex((user)=>user.user_id === req.params.id);
    console.log(userIndex)

    if(userIndex === -1){
        res.status(404).send({'msg': 'user account not found'});
    }

    // remove user from userList
    const deletedUser = usersList.splice(userIndex, 1)[0];
    
    res.status(200).json({msg: `${deletedUser['name']} acct delete successful`});
});

