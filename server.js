'use strict';
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const validDept = d => d === 'taliban' || d === 'us';
const clean = (v,max=500) => String(v ?? '').trim().slice(0,max);
const PORT = Number(process.env.PORT || 3000);
const prod = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || '';
if (prod && sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters in production.');
if (prod && (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 14)) throw new Error('Set ADMIN_PASSWORD to a unique password of at least 14 characters.');
const dbFile = path.resolve(process.env.DATABASE_FILE || './data/gtn-cad.sqlite');
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL, callsign TEXT NOT NULL DEFAULT '', rank TEXT NOT NULL DEFAULT 'Police Officer',
 role TEXT NOT NULL CHECK(role IN ('admin','command','officer')), department TEXT CHECK(department IN ('taliban','us') OR department IS NULL),
 status TEXT NOT NULL DEFAULT 'Off Duty' CHECK(status IN ('Active','Busy','Off Duty')), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS calls (
 id INTEGER PRIMARY KEY AUTOINCREMENT, department TEXT NOT NULL CHECK(department IN ('taliban','us')),
 call_type TEXT NOT NULL, location TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'Routine',
 details TEXT NOT NULL, reporter TEXT NOT NULL DEFAULT 'Anonymous citizen', status TEXT NOT NULL DEFAULT 'Pending',
 assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, department TEXT NOT NULL, record_type TEXT NOT NULL, subject TEXT NOT NULL,
 location TEXT NOT NULL DEFAULT '', officer TEXT NOT NULL DEFAULT '', details TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS crimes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, department TEXT NOT NULL DEFAULT 'both', name TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT 'General', description TEXT NOT NULL DEFAULT '', jail_minutes INTEGER NOT NULL DEFAULT 0,
 fine INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS announcements (
 id INTEGER PRIMARY KEY AUTOINCREMENT, department TEXT NOT NULL DEFAULT 'both', title TEXT NOT NULL,
 body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS strikes_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 actor_id INTEGER,
 action TEXT NOT NULL,
 amount INTEGER NOT NULL DEFAULT 1,
 reason TEXT NOT NULL DEFAULT '',
 strikes_after INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS strike_catalog (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT 'General',
 strikes INTEGER NOT NULL DEFAULT 1,
 other_punishment TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Migration: add strikes column to existing databases
try { db.exec('ALTER TABLE users ADD COLUMN strikes INTEGER NOT NULL DEFAULT 0'); } catch (_) { /* already exists */ }

function strikeLimit(rank) {
  const r = String(rank || '').toLowerCase();
  return r.includes('recruit') ? 3 : 6;
}

// Seed default strike catalog (why officers get strikes + amounts + other punishments)
if (!db.prepare('SELECT COUNT(*) n FROM strike_catalog').get().n) {
 const seedCat = db.prepare('INSERT INTO strike_catalog(name,category,strikes,other_punishment,description) VALUES(?,?,?,?,?)');
 [
  ['Late to shift / no-show','Attendance',1,'Verbal warning','Failing to clock in or missing a scheduled RP shift without notice.'],
  ['RTO / radio misuse','Conduct',1,'Retraining','Unprofessional or spam radio traffic during RP.'],
  ['Failure to follow orders','Conduct',2,'Written warning','Ignoring lawful in-game orders from higher rank.'],
  ['Metagaming / powergaming','Rules',2,'Suspension from patrol (1 shift)','Using OOC knowledge or forcing unrealistic RP outcomes.'],
  ['RDM / VDM involvement','Rules',3,'Temp ban from LEO slots','Random deathmatch or vehicle deathmatch while on duty.'],
  ['Corruption / abuse of power','Serious',3,'Command review; possible demotion','Misusing LEO tools, false arrests, or exploiting rank.'],
  ['Unprofessional behavior (OOC or IC)','Conduct',1,'Coaching session','Harassment, toxicity, or breaking server demeanor standards.'],
  ['Negligent use of force','Force',2,'Force-policy review','Unjustified or excessive force during an RP stop.'],
  ['Leaving post without relief','Attendance',1,'Verbal warning','Abandoning an assigned post or checkpoint early.'],
  ['Failing to file required reports','Admin',1,'Make-up paperwork','Not completing arrest, incident, or warrant paperwork.'],
 ].forEach(x => seedCat.run(...x));
}

const defaultSettings = {
 siteName:'GTN RP CAD', eyebrow:'DAYZ • NASDARA • ROLEPLAY SERVICES', headline:'Grand Theft Nasdara — Police CAD',
 description:'A shared roleplay dispatch and records system for Nasdara. Public crime reports are open to everyone; staff tools require an account.',
 talibanName:'Taliban Police', talibanDescription:'Illegal Town • Local Police', usName:'U.S. Embassy Police', usDescription:'Embassy • Security Police'
};
const setSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
for (const [k,v] of Object.entries(defaultSettings)) if (!db.prepare('SELECT 1 FROM settings WHERE key=?').get(k)) setSetting.run(k,v);
const crimeCount = db.prepare('SELECT COUNT(*) n FROM crimes').get().n;
if (!crimeCount) {
 const seed = db.prepare('INSERT INTO crimes(department,name,category,description,jail_minutes,fine) VALUES(?,?,?,?,?,?)');
 [
 ['both','Trespassing','Property','Entering a restricted RP location without permission.',5,500],
 ['both','Theft','Property','Taking another character’s property without permission.',10,1000],
 ['both','Robbery','Violent Crime','Taking property by threat or force in RP.',15,2000],
 ['both','Assault','Violent Crime','Unlawful physical attack in RP.',10,1000],
 ['taliban','Illegal Weapon Possession','Weapons','Possession contrary to server rules.',10,1500],
 ['us','Embassy Security Violation','Security','Unauthorized entry or interference at the embassy.',15,2000],
 ['both','Failure to Comply','Public Order','Refusing a lawful in-game order under server rules.',5,300]
 ].forEach(x=>seed.run(...x));
}
// System administrator (staff sign-in). Username is stored lowercase so login matching works.
const adminName = clean(process.env.ADMIN_USERNAME || 'gtnadmin', 50).toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || 'GTN-Admin-2026!Secure';
if (adminPassword && !db.prepare('SELECT id FROM users WHERE role="admin" LIMIT 1').get()) {
 const hash = bcrypt.hashSync(adminPassword, 12);
 db.prepare('INSERT OR IGNORE INTO users(username,password_hash,display_name,rank,role,department) VALUES(?,?,?,?,?,NULL)')
   .run(adminName, hash, 'System Administrator', 'Administrator', 'admin');
 console.log(`Created admin/staff account: ${adminName}`);
}

// Seed high-ranking department commanders (one per department, command role).
// These are created only on first run if the username does not already exist.
// Change passwords after first login via Account Management or password reset.
function seedCommander(username, password, displayName, callsign, department) {
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return;
  const hash = bcrypt.hashSync(password, 12);
  db.prepare('INSERT INTO users(username,password_hash,display_name,callsign,rank,role,department,status) VALUES(?,?,?,?,?,?,?,?)')
    .run(username, hash, displayName, callsign, 'Commander', 'command', department, 'Off Duty');
  console.log(`Created ${department.toUpperCase()} Commander account: ${username}`);
}

// U.S. Embassy Police — high-ranking command
seedCommander('us.commander', 'US-Cmd-RP-2026!', 'US Embassy Police Commander', 'CMD-US', 'us');

// Taliban Police — high-ranking command
seedCommander('taliban.commander', 'TB-Cmd-RP-2026!', 'Taliban Police Commander', 'CMD-TB', 'taliban');

// Optional one-time temporary staff / officer account. Configure via environment variables.
// It receives ordinary officer permissions, never admin/command permissions.
const tempStaffName = clean(process.env.TEMP_STAFF_USERNAME, 50).toLowerCase();
const tempStaffPassword = process.env.TEMP_STAFF_PASSWORD || '';
const tempStaffDepartment = clean(process.env.TEMP_STAFF_DEPARTMENT || 'us', 20);
if (tempStaffName && tempStaffPassword) {
 if (tempStaffPassword.length < 12) throw new Error('TEMP_STAFF_PASSWORD must be at least 12 characters.');
 if (!/^[a-z0-9._-]{3,50}$/.test(tempStaffName)) throw new Error('TEMP_STAFF_USERNAME must be 3-50 characters: letters, numbers, dots, underscores, or hyphens.');
 if (!validDept(tempStaffDepartment)) throw new Error('TEMP_STAFF_DEPARTMENT must be either us or taliban.');
 const existingTempStaff = db.prepare('SELECT id FROM users WHERE username=?').get(tempStaffName);
 if (!existingTempStaff) {
  const hash = bcrypt.hashSync(tempStaffPassword, 12);
  db.prepare('INSERT INTO users(username,password_hash,display_name,callsign,rank,role,department) VALUES(?,?,?,?,?,?,?)')
   .run(tempStaffName, hash, clean(process.env.TEMP_STAFF_DISPLAY_NAME || 'Temporary Staff', 100), 'TEMP', 'Temporary Staff', 'officer', tempStaffDepartment);
  console.log(`Created temporary staff account: ${tempStaffName} (${tempStaffDepartment}). Disable it in Account Management when access is no longer needed.`);
 } else {
  console.warn(`TEMP_STAFF_USERNAME '${tempStaffName}' already exists; existing account was not changed.`);
 }
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"], styleSrc:["'self'","'unsafe-inline'"], scriptSrc:["'self'","'unsafe-inline'"], imgSrc:["'self'","data:"], connectSrc:["'self'"] } } }));
app.use(express.json({limit:'32kb'}));
app.use(express.urlencoded({extended:false,limit:'32kb'}));
app.use(session({
 name:'gtncad.sid', secret:sessionSecret || 'development-only-secret-change-this-before-deploying',
 resave:false, saveUninitialized:false, store:new SQLiteStore({db:'sessions.sqlite',dir:path.dirname(dbFile)}),
 cookie:{httpOnly:true, sameSite:'strict', secure:prod, maxAge:8*60*60*1000}
}));
const loginLimiter = rateLimit({windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false, message:{error:'Too many login attempts. Please try again later.'}});
const publicReportLimiter = rateLimit({windowMs:10*60*1000, limit:8, standardHeaders:true, legacyHeaders:false, message:{error:'Too many reports from this connection. Please wait and try again.'}});
function audit(req, action, target='') { db.prepare('INSERT INTO audit_log(actor_id,action,target) VALUES(?,?,?)').run(req.session.user?.id || null, action, clean(target,180)); }
function requireAuth(req,res,next){const u=req.session.user;if(!u)return res.status(401).json({error:'Please sign in first.'});const full=db.prepare('SELECT id,username,display_name,callsign,rank,role,department,status,active,strikes FROM users WHERE id=?').get(u.id);if(!full||!full.active){req.session.destroy(()=>{});return res.status(401).json({error:'Account disabled. Contact an administrator.'});}req.user=full;next();}
function requireRole(...roles){return (req,res,next)=>{if(!req.user||!roles.includes(req.user.role))return res.status(403).json({error:'You do not have permission to do that.'});next();};}
function deptScope(req,res,next){if(req.user.role==='admin')return next();if(!req.user.department)return res.status(403).json({error:'No department assigned.'});next();}
function scopedDept(req){return req.user.role==='admin' ? (validDept(req.query.department)?req.query.department:null) : req.user.department;}
function canManageDepartment(req, dept){return req.user.role==='admin'||(req.user.role==='command'&&req.user.department===dept);}
app.get('/api/health',(req,res)=>res.json({ok:true,service:'GTN RP CAD'}));
app.get('/api/public/settings',(req,res)=>{const rows=db.prepare('SELECT key,value FROM settings').all();res.json(Object.fromEntries(rows.map(x=>[x.key,x.value])));});
app.get('/api/public/announcements',(req,res)=>res.json(db.prepare("SELECT id,department,title,body,created_at FROM announcements ORDER BY id DESC LIMIT 5").all()));
app.post('/api/public/reports',publicReportLimiter,(req,res)=>{
 const department=clean(req.body.department,20), type=clean(req.body.type,80), location=clean(req.body.location,160), reporter=clean(req.body.reporter,80)||'Anonymous citizen', priority=clean(req.body.priority,20), details=clean(req.body.details,1500);
 if(!validDept(department)||!type||!location||!details)return res.status(400).json({error:'Choose a department and provide incident type, location, and description.'});
 if(!['Routine','Urgent','Emergency'].includes(priority))return res.status(400).json({error:'Invalid urgency.'});
 const result=db.prepare('INSERT INTO calls(department,call_type,location,priority,details,reporter,status) VALUES(?,?,?,?,?,?,?)').run(department,type,location,priority,details,reporter,'Pending');
 res.status(201).json({ok:true,callId:result.lastInsertRowid,message:'Report submitted to dispatch.'});
});
app.post('/api/auth/login',loginLimiter,(req,res)=>{
 const username=clean(req.body.username,80).toLowerCase(), password=String(req.body.password||'');
 const user=db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username);
 if(!user||!bcrypt.compareSync(password,user.password_hash))return res.status(401).json({error:'Invalid username or password.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start session.'});req.session.user={id:user.id};req.session.save(err2=>{if(err2)return res.status(500).json({error:'Could not save session.'});audit({session:{user:{id:user.id}}},'login',user.username);res.json({ok:true,user:publicUser(user)});});});
});
function publicUser(u){return {id:u.id,username:u.username,display_name:u.display_name,callsign:u.callsign,rank:u.rank,role:u.role,department:u.department,status:u.status,strikes:u.strikes||0};}
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:req.user}));
app.post('/api/auth/logout',requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie('gtncad.sid',{httpOnly:true,sameSite:'strict',secure:prod});res.json({ok:true});}));
app.get('/api/dashboard',requireAuth,(req,res)=>{
 const dept=scopedDept(req); const where=dept?'WHERE department=?':''; const args=dept?[dept]:[];
 const calls=db.prepare(`SELECT * FROM calls ${where} ORDER BY CASE priority WHEN 'Emergency' THEN 0 WHEN 'Urgent' THEN 1 ELSE 2 END, id DESC LIMIT 100`).all(...args);
 const officers=db.prepare(`SELECT id,username,display_name,callsign,rank,role,department,status FROM users WHERE active=1 AND role IN ('officer','command') ${dept?'AND department=?':''} ORDER BY department,rank,display_name`).all(...args);
 const reports=db.prepare(`SELECT * FROM reports ${where} ORDER BY id DESC LIMIT 30`).all(...args);
 const announcements=db.prepare(`SELECT * FROM announcements WHERE department='both' ${dept?'OR department=?':''} ORDER BY id DESC LIMIT 20`).all(...(dept?[dept]:[]));
 const counts={openCalls:calls.filter(c=>!['Closed','Resolved'].includes(c.status)).length,onDuty:officers.filter(o=>o.status!=='Off Duty').length,reports:reports.length,warrants:reports.filter(r=>r.record_type==='Warrant Request').length};
 res.json({department:dept,calls,officers,reports,announcements,counts});
});
app.get('/api/calls',requireAuth,(req,res)=>{const dept=scopedDept(req);res.json(db.prepare(`SELECT * FROM calls ${dept?'WHERE department=?':''} ORDER BY id DESC LIMIT 200`).all(...(dept?[dept]:[])));});
app.patch('/api/calls/:id',requireAuth,(req,res)=>{const call=db.prepare('SELECT * FROM calls WHERE id=?').get(Number(req.params.id));if(!call)return res.status(404).json({error:'Call not found.'});if(req.user.role!=='admin'&&req.user.department!==call.department)return res.status(403).json({error:'Call belongs to another department.'});const status=clean(req.body.status,30), assigned=clean(req.body.assigned_to,80);if(!['Pending','Dispatched','In Progress','Resolved','Closed'].includes(status))return res.status(400).json({error:'Invalid call status.'});db.prepare('UPDATE calls SET status=?,assigned_to=? WHERE id=?').run(status,assigned,call.id);audit(req,'update_call',String(call.id));res.json({ok:true});});
app.patch('/api/me/status',requireAuth,(req,res)=>{const status=clean(req.body.status,20);if(!['Active','Busy','Off Duty'].includes(status))return res.status(400).json({error:'Invalid status.'});db.prepare('UPDATE users SET status=? WHERE id=?').run(status,req.user.id);audit(req,'change_status',status);res.json({ok:true,status});});
app.get('/api/accounts',requireAuth,(req,res)=>{if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Command access required.'});const dept=req.user.role==='admin'?(validDept(req.query.department)?req.query.department:null):req.user.department;const rows=db.prepare(`SELECT id,username,display_name,callsign,rank,role,department,status,active,strikes,created_at FROM users ${dept?'WHERE department=?':'WHERE role != "admin"'} ORDER BY department,role,display_name`).all(...(dept?[dept]:[]));res.json(rows);});
app.post('/api/accounts',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Command access required.'});
 const username=clean(req.body.username,50).toLowerCase(), password=String(req.body.password||''), display=clean(req.body.display_name,100), callsign=clean(req.body.callsign,40), rank=clean(req.body.rank,50)||'Police Officer';
 const role=clean(req.body.role,20), department=req.user.role==='command'?req.user.department:clean(req.body.department,20);
 if(!/^[a-z0-9._-]{3,50}$/.test(username))return res.status(400).json({error:'Username must be 3–50 characters using letters, numbers, dot, underscore, or hyphen.'});
 if(password.length<12)return res.status(400).json({error:'Set a temporary password of at least 12 characters.'});
 if(!display)return res.status(400).json({error:'Character/display name is required.'});
 if(!validDept(department))return res.status(400).json({error:'Choose a valid department.'});
 if(!['officer','command'].includes(role))return res.status(400).json({error:'Accounts created here must be officers or department commanders.'});
 if(req.user.role==='command'&&role!=='officer')return res.status(403).json({error:'Department command can create officer accounts only.'});
 if(role==='command'&&req.user.role!=='admin')return res.status(403).json({error:'Only the system administrator can appoint department command.'});
 if(role==='command'&&db.prepare('SELECT id FROM users WHERE role="command" AND department=? AND active=1').get(department))return res.status(409).json({error:'This department already has an active command account. Disable it before appointing another.'});
 try{const hash=bcrypt.hashSync(password,12);const result=db.prepare('INSERT INTO users(username,password_hash,display_name,callsign,rank,role,department,status) VALUES(?,?,?,?,?,?,?,?)').run(username,hash,display,callsign,rank,role,department,'Off Duty');audit(req,'create_account',username);res.status(201).json({ok:true,id:result.lastInsertRowid});}
 catch(e){if(String(e.code).includes('SQLITE_CONSTRAINT'))return res.status(409).json({error:'That username is already in use.'});throw e;}
});
app.patch('/api/accounts/:id',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Command access required.'});
 const target=db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.id));
 if(!target)return res.status(404).json({error:'Account not found.'});
 if(target.role==='admin')return res.status(403).json({error:'Administrator accounts cannot be changed here.'});
 if(!canManageDepartment(req,target.department))return res.status(403).json({error:'You cannot manage another department.'});
 if(req.user.role==='command'&&target.role!=='officer')return res.status(403).json({error:'Command can manage officers only.'});
 // Toggle active
 if(req.body.active!==undefined){
  const active=req.body.active===false?0:1;
  db.prepare('UPDATE users SET active=? WHERE id=?').run(active,target.id);
  audit(req,active?'enable_account':'disable_account',target.username);
 }
 // Rank change → strikes reset to 0
 if(req.body.rank!==undefined){
  const newRank=clean(req.body.rank,50);
  if(!newRank)return res.status(400).json({error:'Rank cannot be empty.'});
  if(newRank!==target.rank){
   db.prepare('UPDATE users SET rank=?, strikes=0 WHERE id=?').run(newRank,target.id);
   db.prepare('INSERT INTO strikes_log(user_id,actor_id,action,amount,reason,strikes_after) VALUES(?,?,?,?,?,?)')
    .run(target.id,req.user.id,'rank_up_reset',0,`Rank changed from ${target.rank} to ${newRank}`,0);
   audit(req,'change_rank',`${target.username}:${target.rank}->${newRank}`);
  }
 }
 res.json({ok:true});
});
app.post('/api/accounts/:id/reset-password',requireAuth,(req,res)=>{if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Command access required.'});const target=db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.id));if(!target)return res.status(404).json({error:'Account not found.'});if(target.role==='admin'||!canManageDepartment(req,target.department)||(req.user.role==='command'&&target.role!=='officer'))return res.status(403).json({error:'You cannot reset this account.'});const password=String(req.body.password||'');if(password.length<12)return res.status(400).json({error:'New password must be at least 12 characters.'});db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(password,12),target.id);audit(req,'reset_password',target.username);res.json({ok:true});});

// ─── Strike Board ───────────────────────────────────────────────────────────
// Viewable by all signed-in staff (officers + command + admin).
// Editable (issue / edit strikes & reasons) only by command + admin.
function canViewStrikeDept(req, dept){
 return req.user.role==='admin' || (req.user.department && req.user.department===dept);
}
app.get('/api/strikes',requireAuth,(req,res)=>{
 // All authenticated staff may view the board for their department (admin = all)
 const dept=req.user.role==='admin'?(validDept(req.query.department)?req.query.department:null):req.user.department;
 if(req.user.role!=='admin'&&!dept)return res.status(403).json({error:'No department assigned.'});
 const rows=db.prepare(`SELECT id,username,display_name,callsign,rank,role,department,status,active,strikes FROM users WHERE role IN ('officer','command') ${dept?'AND department=?':''} ORDER BY department, rank, display_name`).all(...(dept?[dept]:[]));
 const lastReasonStmt=db.prepare(`SELECT reason FROM strikes_log WHERE user_id=? AND action IN ('add_strike','strike_and_fire','set_strikes') ORDER BY id DESC LIMIT 1`);
 const enriched=rows.map(u=>{
  const limit=strikeLimit(u.rank);
  const last=lastReasonStmt.get(u.id);
  return {...u, strike_limit:limit, at_limit:(u.strikes||0)>=limit, last_reason:last?last.reason:''};
 });
 res.json({can_edit:['admin','command'].includes(req.user.role), officers:enriched});
});
app.get('/api/strikes/:userId/log',requireAuth,(req,res)=>{
 const target=db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.userId));
 if(!target)return res.status(404).json({error:'Officer not found.'});
 if(target.role==='admin')return res.status(403).json({error:'Cannot view admin strike log.'});
 if(!canViewStrikeDept(req,target.department))return res.status(403).json({error:'You cannot view another department.'});
 const log=db.prepare(`SELECT s.id,s.action,s.amount,s.reason,s.strikes_after,s.created_at,u.username AS actor FROM strikes_log s LEFT JOIN users u ON u.id=s.actor_id WHERE s.user_id=? ORDER BY s.id DESC LIMIT 50`).all(target.id);
 res.json(log);
});
app.post('/api/strikes/:userId',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can issue strikes.'});
 const target=db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.userId));
 if(!target)return res.status(404).json({error:'Officer not found.'});
 if(target.role==='admin')return res.status(403).json({error:'Cannot strike administrator accounts.'});
 if(!canManageDepartment(req,target.department))return res.status(403).json({error:'You cannot manage another department.'});
 if(req.user.role==='command'&&target.role==='command')return res.status(403).json({error:'Command cannot strike other command accounts.'});
 const reason=clean(req.body.reason,300);
 if(!reason)return res.status(400).json({error:'A reason is required when issuing a strike.'});
 const amount=Math.max(1,Math.min(3,Number(req.body.amount)||1));
 let strikes=(target.strikes||0)+amount;
 const limit=strikeLimit(target.rank);
 let fired=false;
 if(strikes>=limit){
  strikes=limit;
  db.prepare('UPDATE users SET strikes=?, active=0 WHERE id=?').run(strikes,target.id);
  fired=true;
  audit(req,'fire_officer',`${target.username} (${strikes}/${limit} strikes)`);
 }else{
  db.prepare('UPDATE users SET strikes=? WHERE id=?').run(strikes,target.id);
 }
 db.prepare('INSERT INTO strikes_log(user_id,actor_id,action,amount,reason,strikes_after) VALUES(?,?,?,?,?,?)')
  .run(target.id,req.user.id,fired?'strike_and_fire':'add_strike',amount,reason,strikes);
 audit(req,'add_strike',`${target.username} +${amount} → ${strikes}/${limit}`);
 res.json({ok:true,strikes,strike_limit:limit,fired,active:fired?0:target.active});
});
app.patch('/api/strikes/:userId',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can edit the strike board.'});
 const target=db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.userId));
 if(!target)return res.status(404).json({error:'Officer not found.'});
 if(target.role==='admin')return res.status(403).json({error:'Cannot edit administrator strikes.'});
 if(!canManageDepartment(req,target.department))return res.status(403).json({error:'You cannot manage another department.'});
 if(req.user.role==='command'&&target.role==='command')return res.status(403).json({error:'Command cannot edit other command strikes.'});
 const limit=strikeLimit(target.rank);
 let strikes=Number(req.body.strikes);
 if(!Number.isInteger(strikes)||strikes<0||strikes>20)return res.status(400).json({error:'Strikes must be a whole number between 0 and 20.'});
 const reason=clean(req.body.reason,300);
 if(!reason)return res.status(400).json({error:'A reason is required when editing strikes.'});
 let fired=false;
 if(strikes>=limit){
  strikes=limit;
  db.prepare('UPDATE users SET strikes=?, active=0 WHERE id=?').run(strikes,target.id);
  fired=true;
  audit(req,'fire_officer',`${target.username} (set to ${strikes}/${limit})`);
 }else{
  db.prepare('UPDATE users SET strikes=? WHERE id=?').run(strikes,target.id);
 }
 db.prepare('INSERT INTO strikes_log(user_id,actor_id,action,amount,reason,strikes_after) VALUES(?,?,?,?,?,?)')
  .run(target.id,req.user.id,'set_strikes',strikes,reason,strikes);
 audit(req,'edit_strikes',`${target.username} → ${strikes}/${limit}`);
 res.json({ok:true,strikes,strike_limit:limit,fired});
});

// ─── Strike Catalog (offense list: why / how many / other punishments) ─────
// Viewable by all signed-in staff. Editable by command + admin only.
app.get('/api/strike-catalog',requireAuth,(req,res)=>{
 const rows=db.prepare('SELECT * FROM strike_catalog WHERE active=1 ORDER BY category,name').all();
 res.json({can_edit:['admin','command'].includes(req.user.role), items:rows});
});
app.post('/api/strike-catalog',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can edit the strike catalog.'});
 const name=clean(req.body.name,120), category=clean(req.body.category,50)||'General';
 const strikes=Number(req.body.strikes), other=clean(req.body.other_punishment,200), description=clean(req.body.description,500);
 if(!name||!Number.isInteger(strikes)||strikes<1||strikes>6)return res.status(400).json({error:'Provide a name and strikes between 1 and 6.'});
 const r=db.prepare('INSERT INTO strike_catalog(name,category,strikes,other_punishment,description) VALUES(?,?,?,?,?)').run(name,category,strikes,other,description);
 audit(req,'create_strike_catalog',name);
 res.status(201).json({ok:true,id:r.lastInsertRowid});
});
app.patch('/api/strike-catalog/:id',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can edit the strike catalog.'});
 const item=db.prepare('SELECT * FROM strike_catalog WHERE id=? AND active=1').get(Number(req.params.id));
 if(!item)return res.status(404).json({error:'Catalog entry not found.'});
 const name=req.body.name!==undefined?clean(req.body.name,120):item.name;
 const category=req.body.category!==undefined?clean(req.body.category,50)||'General':item.category;
 const strikes=req.body.strikes!==undefined?Number(req.body.strikes):item.strikes;
 const other=req.body.other_punishment!==undefined?clean(req.body.other_punishment,200):item.other_punishment;
 const description=req.body.description!==undefined?clean(req.body.description,500):item.description;
 if(!name||!Number.isInteger(strikes)||strikes<1||strikes>6)return res.status(400).json({error:'Provide a name and strikes between 1 and 6.'});
 db.prepare('UPDATE strike_catalog SET name=?,category=?,strikes=?,other_punishment=?,description=? WHERE id=?').run(name,category,strikes,other,description,item.id);
 audit(req,'edit_strike_catalog',name);
 res.json({ok:true});
});
app.delete('/api/strike-catalog/:id',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can edit the strike catalog.'});
 const item=db.prepare('SELECT * FROM strike_catalog WHERE id=? AND active=1').get(Number(req.params.id));
 if(!item)return res.status(404).json({error:'Catalog entry not found.'});
 db.prepare('UPDATE strike_catalog SET active=0 WHERE id=?').run(item.id);
 audit(req,'remove_strike_catalog',item.name);
 res.json({ok:true});
});

app.get('/api/crimes',requireAuth,(req,res)=>{const dept=scopedDept(req);res.json(db.prepare(`SELECT * FROM crimes WHERE active=1 AND (department='both' ${dept?'OR department=?':''}) ORDER BY category,name`).all(...(dept?[dept]:[])));});
app.post('/api/crimes',requireAuth,(req,res)=>{if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can add charges.'});const dept=req.user.role==='command'?req.user.department:clean(req.body.department,20);const name=clean(req.body.name,100),category=clean(req.body.category,50)||'General',description=clean(req.body.description,500),jail=Number(req.body.jail_minutes),fine=Number(req.body.fine);if(!(validDept(dept)||dept==='both')||!name||!Number.isInteger(jail)||jail<0||jail>1440||!Number.isInteger(fine)||fine<0||fine>1000000)return res.status(400).json({error:'Check the charge fields and penalty limits.'});if(req.user.role==='command'&&dept==='both')return res.status(403).json({error:'Command can only add charges for their own department.'});const r=db.prepare('INSERT INTO crimes(department,name,category,description,jail_minutes,fine) VALUES(?,?,?,?,?,?)').run(dept,name,category,description,jail,fine);audit(req,'create_crime',name);res.status(201).json({ok:true,id:r.lastInsertRowid});});
app.patch('/api/crimes/:id',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can edit charges.'});
 const crime=db.prepare('SELECT * FROM crimes WHERE id=?').get(Number(req.params.id));
 if(!crime||!crime.active)return res.status(404).json({error:'Charge not found.'});
 if(req.user.role==='command'&&crime.department!=='both'&&crime.department!==req.user.department)return res.status(403).json({error:'You can only edit charges for your department.'});
 if(req.user.role==='command'&&crime.department==='both')return res.status(403).json({error:'Only administrators can edit shared (both) charges.'});
 const name=req.body.name!==undefined?clean(req.body.name,100):crime.name;
 const category=req.body.category!==undefined?clean(req.body.category,50)||'General':crime.category;
 const description=req.body.description!==undefined?clean(req.body.description,500):crime.description;
 const jail=req.body.jail_minutes!==undefined?Number(req.body.jail_minutes):crime.jail_minutes;
 const fine=req.body.fine!==undefined?Number(req.body.fine):crime.fine;
 let dept=crime.department;
 if(req.body.department!==undefined){
  dept=req.user.role==='command'?req.user.department:clean(req.body.department,20);
 }
 if(!name||!Number.isInteger(jail)||jail<0||jail>1440||!Number.isInteger(fine)||fine<0||fine>1000000)return res.status(400).json({error:'Check the charge fields and penalty limits.'});
 if(!(validDept(dept)||dept==='both'))return res.status(400).json({error:'Invalid department.'});
 db.prepare('UPDATE crimes SET department=?,name=?,category=?,description=?,jail_minutes=?,fine=? WHERE id=?').run(dept,name,category,description,jail,fine,crime.id);
 audit(req,'edit_crime',name);
 res.json({ok:true});
});
app.delete('/api/crimes/:id',requireAuth,(req,res)=>{
 if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Only department command and administrators can remove charges.'});
 const crime=db.prepare('SELECT * FROM crimes WHERE id=?').get(Number(req.params.id));
 if(!crime||!crime.active)return res.status(404).json({error:'Charge not found.'});
 if(req.user.role==='command'&&(crime.department==='both'||crime.department!==req.user.department))return res.status(403).json({error:'You can only remove charges for your department.'});
 db.prepare('UPDATE crimes SET active=0 WHERE id=?').run(crime.id);
 audit(req,'remove_crime',crime.name);
 res.json({ok:true});
});
app.get('/api/announcements',requireAuth,(req,res)=>{const dept=scopedDept(req);res.json(db.prepare(`SELECT * FROM announcements WHERE department='both' ${dept?'OR department=?':''} ORDER BY id DESC LIMIT 100`).all(...(dept?[dept]:[])));});
app.post('/api/announcements',requireAuth,(req,res)=>{if(!['admin','command'].includes(req.user.role))return res.status(403).json({error:'Command access required.'});const dept=req.user.role==='command'?req.user.department:clean(req.body.department,20);const title=clean(req.body.title,120),body=clean(req.body.body,2000);if(!(validDept(dept)||dept==='both')||!title||!body)return res.status(400).json({error:'Provide a title, message, and valid department.'});const r=db.prepare('INSERT INTO announcements(department,title,body) VALUES(?,?,?)').run(dept,title,body);audit(req,'create_announcement',title);res.status(201).json({ok:true,id:r.lastInsertRowid});});
app.get('/api/settings',requireAuth,requireRole('admin'),(req,res)=>res.json(Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]))));
app.put('/api/settings',requireAuth,requireRole('admin'),(req,res)=>{const allowed=Object.keys(defaultSettings);for(const key of allowed){if(req.body[key]!==undefined)setSetting.run(key,clean(req.body[key],key==='description'?1000:180));}audit(req,'update_site_settings','homepage');res.json({ok:true});});
app.get('/api/audit',requireAuth,requireRole('admin'),(req,res)=>res.json(db.prepare('SELECT a.id,a.action,a.target,a.created_at,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200').all()));
app.get('/api/reports',requireAuth,(req,res)=>{const dept=scopedDept(req);res.json(db.prepare(`SELECT * FROM reports ${dept?'WHERE department=?':''} ORDER BY id DESC LIMIT 200`).all(...(dept?[dept]:[])));});
app.post('/api/reports',requireAuth,(req,res)=>{const department=req.user.role==='admin'?clean(req.body.department,20):req.user.department;const type=clean(req.body.record_type,60),subject=clean(req.body.subject,120),location=clean(req.body.location,160),officer=clean(req.body.officer,100)||req.user.display_name,details=clean(req.body.details,3000);if(!(validDept(department))||!type||!subject||!details)return res.status(400).json({error:'Complete all required record fields.'});const r=db.prepare('INSERT INTO reports(department,record_type,subject,location,officer,details) VALUES(?,?,?,?,?,?)').run(department,type,subject,location,officer,details);audit(req,'create_report',String(r.lastInsertRowid));res.status(201).json({ok:true,id:r.lastInsertRowid});});
function searchReports(q, filter, dept){
 let typeClause='';
 const args=[];
 if(q){typeClause+=' AND (subject LIKE ? OR details LIKE ? OR officer LIKE ?)';args.push(`%${q}%`,`%${q}%`,`%${q}%`);}
 if(filter==='arrest'){typeClause+=" AND record_type LIKE '%Arrest%'";}
 else if(filter==='warrant'){typeClause+=" AND record_type LIKE '%Warrant%'";}
 else if(filter==='fine'||filter==='citation'){typeClause+=" AND (record_type LIKE '%Citation%' OR record_type LIKE '%Fine%' OR details LIKE '%fine%')";}
 if(dept){typeClause+=' AND department=?';args.push(dept);}
 return db.prepare(`SELECT id,subject,record_type,location,officer,details,created_at,department FROM reports WHERE 1=1 ${typeClause} ORDER BY id DESC LIMIT 150`).all(...args);
}
const publicSearchLimiter = rateLimit({windowMs:10*60*1000, limit:30, standardHeaders:true, legacyHeaders:false, message:{error:'Too many searches from this connection. Please wait and try again.'}});
// Public record search — no sign-in required
app.get('/api/public/person-search',publicSearchLimiter,(req,res)=>{
 const q=clean(req.query.q,80);
 const filter=clean(req.query.filter,40).toLowerCase();
 res.json(searchReports(q, filter, null));
});
// Staff record search (same data; kept for authenticated clients)
app.get('/api/person-search',requireAuth,(req,res)=>{
 const q=clean(req.query.q,80);
 const filter=clean(req.query.filter,40).toLowerCase();
 const dept=scopedDept(req);
 res.json(searchReports(q, filter, dept));
});
app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});
app.listen(PORT,()=>console.log(`GTN RP CAD listening on port ${PORT}`));
