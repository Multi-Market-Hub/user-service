import { User, createUser } from '../Models/UserModel';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import userSchema from '../UserSchema';

const RegisterUser = async (data: User) => {
    const validate = userSchema.safeParse(data);
    if (!validate.success) {
        throw new Error('Invalid request data');
    }
    const { firstname, lastname, email, password, isAdmin = false } = validate.data;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const generateUserUUID = uuidv4();

    const newUser = await createUser({
        id: generateUserUUID,
        firstname,
        lastname,
        email,
        password: hashedPassword,
        isAdmin,
    });
    return newUser;
};

export default RegisterUser;

