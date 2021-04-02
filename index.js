require('dotenv').config();
var express = require('express');
const session = require('express-session');
const expressip = require('express-ip');
const path = require('path');
var bodyParser = require('body-parser');
var urlencodedParser = bodyParser.urlencoded({ extended: false });
var ejs = require('ejs');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var moment = require('moment');
const request = require('request');
const cryptoRandomString = require('crypto-random-string');
const PORT = process.env.PORT || 5000;
const helmet = require('helmet');
var pull = require('array-pull');
const ytdl = require('ytdl-core');
var ytpl = require('ytpl');
const getVideoId = require('get-video-id');
var MongoDBStore = require('connect-mongodb-session')(session);
var useragent = require('express-useragent');
const rateLimit = require("express-rate-limit");
var MongoStore = require('rate-limit-mongo');
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPT_KEY);
const sendSeekable = require('send-seekable');
const https = require('https');

////////////////////////////////////////////////////////////////////////
var server = 1;
var browser_version = 'e'; //'Gecko/78.0';
var time_limit = 500000000000000;
var test_token = 'd4c3f6d71547808f3fe90669e14450147c02515360552105437383e73e2b6770b47c9b6b7946dc69d4cafee202631e4ba38b5f274cc574deebadac0ee5143992435e3e536ccd65807f2e1dea33564d91df745bac63829179809c9044549e564fbe6ab97d2d3cc06edf2e9aa061c5652e6301aaaaedeb041b1d185f464e91648ce650d0c977b2394fb9494b0cc940229dcb2380fa491d482d6582b9971cc1633575b45de08960910d03b2ced6e5c3255f7c48d81c00d44a1c007166522f92303729147f974934c4263d68be1249d8a4e9693d1306a3a20c661565fe3f88622fc764d1e2abb297dcd0ed9955d678fecfd118744e272d9233076db850ceecab4c93da90b597ab29d54ce4ab8f0d4525862a5034fd968599c99fd8ca575594bf6ba3c942c3d6065ae069c7fa181558c6727914d679584f85dae927990ae13850fbc5332848655be3a1eeeb82f5f78c86bd7335e4b3b1a30fb2c7556a23c4184a793d0ac73753dd27e0a36a128c'
////////////////////////////////////////////////////////////////////////



const error_token = cryptr.decrypt(process.env.ERROR_TOKEN);



var app = express();
app.use(useragent.express());
app.use(expressip().getIpInfoMiddleware);
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/views'));
app.use(sendSeekable);
app.use(
    helmet({
        contentSecurityPolicy: false,
    })
);

app.use(function(req, res, next) {
    var url_schema = req.headers['x-forwarded-proto'];

    if (url_schema === 'https') {
        next();
    } else {
        res.redirect('https://' + req.headers.host + req.url);
    }
});

// redirect to any url except the present one

var template = '<script type="text/javascript"> window.location.href="about:blank"; </script>';


var limiter = new rateLimit({
    store: new MongoStore({
        uri: process.env.USERRATE_LIMIT,
        // should match windowMs
        collectionName: 'userRateLimit',
        expireTimeMs: 15 * 60 * 1000,
        errorHandler: console.error.bind(null, 'rate-limit-mongo')
        // see Configuration section for more options and details
    }),
    message: template,
    max: 100,
    // should match expireTimeMs
    windowMs: 15 * 60 * 1000
});

//  apply to all requests
app.set('trust proxy', 1);
app.use(limiter);


// cookie storage 
var store = new MongoDBStore({
    uri: process.env.USER_SESSIONS,
    collection: 'userSessions',
    expires: 1000 * 60 * 60 * 24, // cookie expire in mongo 24 hrs
    connectionOptions: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 10000
    }
});

store.on('error', function(error) {
    if (err) {
        console.log('CANT CONNECT TO MongoDBStore !!!');
        console.log(error);
    }
});

app.use(session({
    secret: 'U5EAM0SCAD37CLjpLp7a',
    cookieName: "OMWC",
    saveUninitialized: true,
    resave: true,
    store: store,
    cookie: {
        maxAge: 3 * 60 * 60 * 1000 // 60 seconds
    }
}));




var user_details_server = new Schema({
    username: {
        type: String,
        unique: true
    },
    password: String,
    branch: String,
    phonenumber: {
        type: Number,
        unique: true
    },
    phoneverified: Boolean,
    unique_id: {
        type: String,
        unique: true
    },
    logincount: Number,
    video_watch_hour: Number,
    points: Number,
    rank: Number,
    token_coins: Number,
    like: { type: [String], default: undefined },
    dislike: { type: [String], default: undefined },
    userblocked: Boolean,
    block_reason: String,
    server: Number
}, {
    collection: 'user_details'
});
//username, password, branch, phonenumber, phoneverified, unique_id, logincount, video_watch_hour, points, rank, token_coins, like, dislike, userblocked, block_reason
var connect1 = mongoose.createConnection(process.env.USER_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var user_details_model = connect1.model('user_details_model', user_details_server);

var subjectlist_server = new Schema({
    branch: String,
    subject: String,
    playlist: String,
    lec_num: Number,
    lec_name: String,
    lec_time: String,
    sublike: Number,
    subdislike: Number,
    views: Number,
    comments: [{
        commentor: String,
        rank: Number,
        commentor_msg: String
    }]
}, {
    collection: 'subjectlist_details'
});


var connect2 = mongoose.createConnection(process.env.SUBJECTLIST_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var subjectlist_model = connect2.model('subjectlist_model', subjectlist_server);


app.get('/registration_page', function(req, res) {
    var sess = req.session;
    try {
        //var token = JSON.parse(cryptr.decrypt(req.query.token));
        var token = JSON.parse(cryptr.decrypt(test_token))
        sess.browser_validity = req.useragent.source;
        sess.unique_id = token.unique_id;
        sess.user_ip = token.user_ip;
        sess.user_country = token.user_country;
        sess.user_city = token.user_city;
        sess.user_state = token.user_state;
        sess.build_product = token.build_product;
        sess.build_model = token.build_model;
        sess.build_manufacturer = token.build_manufacturer;
        var past_time = token.timestamp;
        var present_time = moment().format('x');
        var time_diff = present_time - past_time;
        if (sess.user_ip == req.ip && time_diff <= time_limit && sess.browser_validity.includes(browser_version)) {
            res.render("registration.ejs");
        } else {
            res.render("error.ejs");
        }
    } catch (error) {
        console.log('Error in /registration_page route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : registration_page on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs");
    }
})


app.post('/registration', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        sess.browser_validity = req.useragent.source;
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response = {
                username: req.body.username,
                password: req.body.password,
                branch: req.body.branch,
                phonenumber: req.body.phonenumber,
                phoneverified: false,
                unique_id: sess.unique_id,
                logincount: 0,
                video_watch_hour: 0,
                points: 0,
                rank: 0,
                token_coins: 100,
                like: [],
                dislike: [],
                userblocked: true,
                block_reason: "Nil",
                server: 0
            };
            user_details_model.create(response, function(err, result) {
                if (err) {
                    if (err.code === 11000) {
                        // duplicate 
                        var error_json = err.keyPattern;
                        var error_key = Object.keys(error_json);
                        var response_result = { form_dupname: "username" == error_key, form_dupdev: "unique_id" == error_key, form_dupphone: "phonenumber" == error_key, form_success: false };
                        console.log(response_result);
                        res.end(JSON.stringify(response_result));
                    }
                } else {
                    var username_update = "__Username__ : " + req.body.username;
                    var unique_id_update = "__Unique ID__ : " + sess.unique_id;
                    var user_state_update = "__State__ : " + sess.user_state;
                    new_reg_bot.sendMessage(telegram_admin, username_update + "\r\n" + unique_id_update + "\r\n" + user_state_update).then(function(resp) {
                        console.log('ADMIN informed about new User ' + req.body.username + '!!!')
                    }).catch(function(error) {
                        if (error.response && error.response.statusCode === 403) {
                            console.log("ADMIN is not connected to o2plus_newuser_bot !!!");
                        }
                    });
                    var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: true };
                    res.end(JSON.stringify(response_result));
                }
            })
        } else {
            var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: false };
            res.end(JSON.stringify(response_result));
        }
    } catch (error) {
        console.log('Error in /registration route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : registration on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: false };
        res.end(JSON.stringify(response_result));
    }
})

app.get('/first_time_registration', function(req, res) {
    res.render("first_time_registration.ejs");
})


app.get('/login_page', function(req, res) {
    var sess = req.session;
    try {
        //var token = JSON.parse(cryptr.decrypt(req.query.token));
        var token = JSON.parse(cryptr.decrypt(test_token))
        sess.browser_validity = req.useragent.source;
        sess.unique_id = token.unique_id;
        sess.user_ip = token.user_ip;
        sess.user_country = token.user_country;
        sess.user_city = token.user_city;
        sess.user_state = token.user_state;
        sess.build_product = token.build_product;
        sess.build_model = token.build_model;
        sess.build_manufacturer = token.build_manufacturer;
        var past_time = token.timestamp;
        var present_time = moment().format('x');
        var time_diff = present_time - past_time;
        console.log(sess.user_ip == req.ip);
        console.log(time_diff <= time_limit);
        console.log(sess.browser_validity.includes(browser_version));
        if (sess.user_ip == req.ip && time_diff <= time_limit && sess.browser_validity.includes(browser_version)) {
            res.render("login.ejs");
        } else {
            res.render("error.ejs");
        }
    } catch (err) {
        console.log('Error in /login_page route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(err);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + err;
        var err_location = "__Error Location__ : login_page on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message);
        res.render("error.ejs");
    }
});


app.post('/login', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response = { username: req.body.username, password: req.body.password, unique_id: sess.unique_id };
            database_search({ username: req.body.username }).then(function(result) {
                if (result) {
                    if (response.username == result.username && response.password == result.password && sess.unique_id == result.unique_id) {
                        sess.username = result.username;
                        sess.password = result.password;
                        sess.branch = result.branch;
                        sess.phonenumber = result.phonenumber;
                        sess.phoneverified = result.phoneverified;
                        sess.unique_id = result.unique_id
                        sess.logincount = result.logincount;
                        sess.video_watch_hour = result.video_watch_hour;
                        sess.points = result.points;
                        sess.rank = result.rank;
                        sess.token_coins = result.token_coins
                        sess.like = result.like;
                        sess.dislike = result.dislike;
                        sess.userblocked = result.userblocked;
                        // need to fix the phone verification condition
                        if (sess.userblocked == true) {
                            var response_result = { form_ver: 'valid pswd', form_redirect: 'first_time_registration' };
                            res.end(JSON.stringify(response_result));
                        } else {
                            sess.logincount = sess.logincount + 1;
                            user_details_model.aggregate([{ $match: { points: { $gte: sess.points } } }, { $count: "user_ranking" }]).exec(function(err, result) {
                                sess.rank = result[0].user_ranking;
                                updatevalue({ username: sess.username, unique_id: sess.unique_id }, { logincount: sess.logincount, rank: result[0].user_ranking });
                                user_details_model.count({}, function(err, count) {
                                    sess.total_users = count;
                                    var response_result = { form_ver: 'valid pswd', form_redirect: 'home' };
                                    res.end(JSON.stringify(response_result));
                                })
                            })
                        }
                    } else if (response.username == result.username && response.password == result.password && response.unique_id != result.unique_id) {
                        var response_result = { form_ver: 'dup device', form_redirect: '' };
                        res.end(JSON.stringify(response_result));
                    } else {
                        var response_result = { form_ver: 'invalid pswd', form_redirect: '' };
                        res.end(JSON.stringify(response_result));
                    }
                } else {
                    var response_result = { form_ver: 'invalid user', form_redirect: '' };
                    res.end(JSON.stringify(response_result));
                }
            });
        } else {
            var response_result = { form_ver: 'invalid user', form_redirect: '' };
            res.end(JSON.stringify(response_result));
        }
    } catch (error) {
        console.log('Error in /login route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : login on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404);
    }
})


async function database_search(search_parameters) {
    let promise = new Promise((resolve, reject) => {
        user_details_model.find(search_parameters, function(err, result) {
            if (err) {
                console.log(err);
                resolve(null);
                res.end('failed');
            } else {
                resolve(result[0]);
            }
        })
    }).catch(error => {
        resolve(null);
        console.log(error)
    })
    let resultfinal = await promise;
    return resultfinal; // "done!"
}

async function updatevalue(search_value, newupdatevalue) {
    let promise = new Promise((resolve, reject) => {
        user_details_model.findOneAndUpdate(search_value, { $set: newupdatevalue }, { new: true }, (err, doc) => {
            if (err) {
                console.log("Something wrong when updating data!");
                resolve('fail');
            }
            console.log(doc);
            resolve('success');
        });
    }).catch(error => {
        resolve('fail');
        console.log(error)
    })
    let resultfinal = await promise;
    return resultfinal;
}

app.get('/home', function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            //username, password, branch, phonenumber, phoneverified, unique_id, logincount, video_watch_hour, points, rank, token_coins, like, dislike, userblocked, block_reason
            var response = {
                username: sess.username,
                branch: sess.branch,
                phonenumber: sess.phonenumber,
                points: sess.points,
                rank: sess.rank,
                token_coins: sess.token_coins,
                userblocked: sess.userblocked
            };
            console.log(response)
            res.render('home.ejs', response);
        } else {
            res.render("error.ejs");
        }
    } catch (error) {
        console.log('Error in /home route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : home on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs")
    }
});



app.get('/lecture', function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            res.render(sess.branch + '_subjectlist.ejs');
        } else {
            res.render('error.ejs')
        }
    } catch (error) {
        console.log('Error in /lecture route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : lecture on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs")
    }
})



app.get('/playlist', function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            sess.subject = req.query.subject;
            res.render('playlist.ejs');
        } else {
            res.render('error.ejs');
        }
    } catch (error) {
        console.log('Error in /playlist route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : playlist on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs")
    }
})


app.post('/playlist_info', urlencodedParser, async function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response_code = { branch: sess.branch, subject: sess.subject };
            var query_code = { lec_num: 1, lec_name: 1 }
            subjectlist_model.find(response_code, query_code).sort({ $natural: -1 }).exec(function(err, result) {
                console.log(result);
                res.send(JSON.stringify(result));
            })
        }
    } catch (error) {
        console.log('Error in /playlist_info route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : playlist_info on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404)
    }
})


app.get('/player', function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            sess.lec_num = req.query.lec_num;
            var response_code = { branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num };
            subjectlist_model.findOne(response_code, { lec_name: 1, sublike: 1, subdislike: 1, views: 1, playlist: 1 }, function(err, data) {
                if (err) { console.log(err); };
                sess.sublike = data.sublike;
                sess.subdislike = data.subdislike;
                sess.views = data.views;
                sess.playlist = data.playlist;
                //console.log(req.protocol+"://" + req.get("host"));
                ytpl(data.playlist).then(info => {
                    video_url = info.items[0].shortUrl;
                    video_url_name = info.items[0].title;
                    video_url_id = getVideoId(info.items[0].shortUrl).id;
                    sess.video_url_id = video_url_id;
                    if (sess.like.includes(sess.subject + ':' + sess.lec_num)) {
                        var like_status = true;
                        res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    } else if (sess.dislike.includes(sess.subject + ':' + sess.lec_num)) {
                        var like_status = false;
                        res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    } else {
                        var like_status = '';
                        res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    }
                    //    ytdl.getInfo(video_url_id).then(info_data => {
                    //        vid_container = [];
                    //        for (var i = 0; i < info_data.formats.length; i++) {
                    //            if (info_data.formats[i].hasVideo == true && info_data.formats[i].hasAudio == true) {
                    //                vid_container.push(info_data.formats[i]);
                    //            }
                    //            if (i == info_data.formats.length - 1) {
                    //                let formatv = vid_container[0];
                    //                sess.videolink = formatv.url;
                    //                console.log(sess);
                    //            }
                    //        }
                    //        if (sess.like.includes(sess.subject + ':' + sess.lec_num)) {
                    //            var like_status = true;
                    //            res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    //        } else if (sess.dislike.includes(sess.subject + ':' + sess.lec_num)) {
                    //            var like_status = false;
                    //            res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    //        } else {
                    //            var like_status = '';
                    //            res.render('player.ejs', { ip_address: sess.user_ip, username: sess.username, phonenumber: sess.phonenumber, branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num, lec_name: data.lec_name, like: data.sublike, dislike: data.subdislike, like_status: like_status, views: data.views });
                    //        }
                    //    })
                })
            })
        } else {
            res.render('error.ejs');
        }
    } catch (error) {
        console.log('Error in /player route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : player on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs")
    }
})


app.post('/grimlim', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response_code = { branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num };
            subjectlist_model.findOneAndUpdate(response_code, { $set: { "views": sess.views + 1 } }, { new: true }, function(err, data) {
                if (err) { console.log(err); }
                sess.views = sess.views + 1;
                console.log(data);
            })
            var response_code = { fv: req.protocol + "://" + req.get("host") + "/stream" };
            res.send(JSON.stringify(response_code));
        }
    } catch (error) {
        console.log('Error in /grimlim route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : grimlim on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404)
    }
})

app.get('/stream', function(req, res) {
    var sess = req.session;
    console.log(sess.video_url_id);
    try {
        ytdl.getInfo(sess.video_url_id).then(info_data => {
            vid_container = [];
            for (var i = 0; i < info_data.formats.length; i++) {
                if (info_data.formats[i].hasVideo == true && info_data.formats[i].hasAudio == true) {
                    vid_container.push(info_data.formats[i]);
                }
                if (i == info_data.formats.length - 1) {
                    let formatv = vid_container[0];
                    https.get(formatv.url, function(response) {
                        res.sendSeekable(response, {
                            connection: 'keep-alive',
                            "cache-control": "no-cache",
                            type: 'video/mp4', // e.g. 'audio/mp4'
                            length: formatv.contentLength,
                            filename: 'stream.mp4' // e.g. 4287092
                        });
                    });

                }
            }
        })
    } catch (error) {
        console.log(error)
    }
})

app.post('/player_comment_preload', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response_code = { branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num };
            subjectlist_model.findOne(response_code, { comments: 1 }, function(err, data) {
                if (err) {
                    console.log(err);
                } else {
                    var data_temp = data.comments;
                    res.send(JSON.stringify(data_temp));
                }
            })
        }
    } catch (error) {
        console.log('Error in /player_comment_preload route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : player_comment_preload on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404)
    }
})

app.post('/player_comment', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response_code = { branch: sess.branch, subject: sess.subject, lec_num: sess.lec_num };
            var comment_temp = { commentor: sess.username, rank: sess.rank, commentor_msg: req.body.comment_msg };
            subjectlist_model.findOne(response_code, { comments: 1 }, function(err, data) {
                var data_temp = data.comments;
                if (data_temp.length < 50) {
                    data_temp.push(comment_temp);
                } else {
                    data_temp.pop(comment_temp);
                    data_temp.push(comment_temp);
                }
                subjectlist_model.findOneAndUpdate(response_code, { $set: { comments: data_temp } }, { new: true }, function(err, data) {
                    res.send(JSON.stringify(comment_temp));
                })
            })
        }
    } catch (error) {
        console.log('Error in /player_comment route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : player_comment on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404)
    }
})





app.post('/vote', urlencodedParser, function(req, res) {
    var sess = req.session;
    try {
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            if (req.body.vote == "") {
                pull(sess.dislike, sess.subject + ':' + sess.lec_num);
                pull(sess.like, sess.subject + ':' + sess.lec_num);
                sess.sublike = req.body.like_value;
                sess.subdislike = req.body.dislike_value;
                user_details_model.findOneAndUpdate({ "username": sess.username }, { $set: { "like": sess.like, "dislike": sess.dislike } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                subjectlist_model.findOneAndUpdate({ "branch": sess.branch, "subject": sess.subject, "lec_num": sess.lec_num }, { $set: { "sublike": req.body.like_value, "subdislike": req.body.dislike_value } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                res.send(JSON.stringify({ like: sess.like, dislike: sess.dislike, sublike: sess.sublike, subdislike: sess.subdislike }));
            }

            if (req.body.vote == "true") {
                pull(sess.dislike, sess.subject + ':' + sess.lec_num);
                sess.like.push(sess.subject + ':' + sess.lec_num);
                sess.sublike = req.body.like_value;
                sess.subdislike = req.body.dislike_value;
                user_details_model.findOneAndUpdate({ "username": sess.username }, { $set: { "like": sess.like, "dislike": sess.dislike } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                subjectlist_model.findOneAndUpdate({ "branch": sess.branch, "subject": sess.subject, "lec_num": sess.lec_num }, { $set: { "sublike": req.body.like_value, "subdislike": req.body.dislike_value } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                res.send(JSON.stringify({ like: sess.like, dislike: sess.dislike, sublike: sess.sublike, subdislike: sess.subdislike }));
            }

            if (req.body.vote == "false") {
                pull(sess.like, sess.subject + ':' + sess.lec_num);
                sess.dislike.push(sess.subject + ':' + sess.lec_num);
                sess.sublike = req.body.like_value;
                sess.subdislike = req.body.dislike_value;
                user_details_model.findOneAndUpdate({ "username": sess.username }, { $set: { "like": sess.like, "dislike": sess.dislike } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                subjectlist_model.findOneAndUpdate({ "branch": sess.branch, "subject": sess.subject, "lec_num": sess.lec_num }, { $set: { "sublike": req.body.like_value, "subdislike": req.body.dislike_value } }, { new: true }, function(err, data) {
                    console.log(data);
                })
                res.send(JSON.stringify({ like: sess.like, dislike: sess.dislike, sublike: sess.sublike, subdislike: sess.subdislike }));
            }
        }
    } catch (error) {
        console.log('Error in /vote route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : vote on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.status(404)
    }
})



function telegram_route_error_bot(message) {
    request.get('https://o2plus-telegram1.herokuapp.com/helloworld', function(error, getresult) {
        request.post('https://o2plus-telegram1.herokuapp.com/error', { form: { message: message } }, function(err, postresult) {
            console.log(postresult);
        })
    })
}


app.listen(PORT, function() { console.log('Server Started !!!') });