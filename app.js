require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');

// middlewares
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// variables
const port = process.env.PORT || 3000;
// const jwtsecret = process.env.JWT_SECRET;
// const secretkey = process.env.SECRET_KEY;


// temporal database
const usersList = []; //On production app, replace with real DB

app.listen(port, ()=>{console.log(`server running on port ${port}`)});




//*******************
//      ROUTES
//******************* 
// get all user registered in database
app.get('/users', (req, res)=>{
    console.log('all users');
    res.json(usersList);
});


// create a new user
app.post('/signup', async(req, res)=>{
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
    const user = usersList.find((user)=>user.name === req.body.name);
    
    if (user == null) {
        res.status(400).send({'msg':'user not found'})
    }

    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            console.info('log-in successful')
            res.status(200).send({'msg':`${user.name} log-in successful`})
        }else{
            res.status(400).send({'msg':'log-in failed'})
        }
    } catch (err) {
        res.status(500).send();
    }
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
    res.status(200).json({msg: 'log-out successful'});
});


// delete user
app.get('/user/delete/:id', (req, res)=>{
    const userIndex = usersList.findIndex((user)=>user.user_id === req.params.id);
    console.log(userIndex)

    if(userIndex === -1){
        res.status(404).send({'msg': 'user account not found'});
    }

    // remove user form userList
    const deletedUser = usersList.splice(userIndex, 1)[0];
    
    res.status(200).json({msg: `${deletedUser['name']} acct delete successful`});
});
