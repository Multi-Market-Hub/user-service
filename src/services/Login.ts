import bcrypt from 'bcrypt';
import { BasicUser } from '../Models/UserModel';
import { login } from '../Models/UserModel';

const LoginUser = (data: BasicUser) => {
    return new Promise((resolve, reject) => {
        const { password } = data;
        login(data).then((user) => {
            if (!user) {
                return reject(new Error('User not found'));
            }
            bcrypt.compare(password, user.password).then((checkPassword) => {
                if (!checkPassword) {
                    return reject(new Error('Incorrect password'));
                }
                resolve(user); // Ensure this resolves with the correct user object
            }).catch((error) => {
                reject(error);
            });
        }).catch((error) => {
            reject(error);
        });
    });
};

export default LoginUser;