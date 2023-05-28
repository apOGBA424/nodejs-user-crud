const express = require('express');
const router = express.Router;

const {publicPosts, privatePosts} = require('../db.js')

router.get('/free', (req, res)=>{
    res.json({publicPosts});
});

router.get('/paid', (req, res)=>{
    res.json({privatePosts});
});



module.exports = {
    router,
}