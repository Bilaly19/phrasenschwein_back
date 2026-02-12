const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

async function registerUser(readUsers, writeUsers, usersPath, username, password) {
  const usersData = await readUsers(usersPath);

  if (usersData.users?.[username]) {
    return false;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  usersData.users[username] = {
    passwordHash,
    createdAt: new Date().toISOString()
  };

  await writeUsers(usersPath, usersData);
  return true;
}

async function loginUser(readUsers, writeUsers, usersPath, username, password, buildSession) {
  const usersData = await readUsers(usersPath);
  const user = usersData.users?.[username];

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return null;
  }

  const token = uuidv4();
  usersData.sessions[token] = buildSession(username);
  await writeUsers(usersPath, usersData);

  return { token, username };
}

async function logoutUser(readUsers, writeUsers, usersPath, token, resolveSession) {
  if (!token) {
    return;
  }

  const usersData = await readUsers(usersPath);
  const session = resolveSession(usersData.sessions, token);

  if (session) {
    delete usersData.sessions[token];
    await writeUsers(usersPath, usersData);
  }
}

module.exports = {
  registerUser,
  loginUser,
  logoutUser
};
