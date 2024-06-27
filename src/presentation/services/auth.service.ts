import { JwtAdapter, bcryptAdapter, envs } from "../../config";
import { UserModel } from "../../data";
import { CustomError, RegisterUserDto, LoginUserDto, UserEntity } from "../../domain";
import { EmailService } from "./email.service";


export class AuthService {

    //Di
    constructor(

        private readonly emailService: EmailService

    ){}

    public async registerUser( registerUserDto: RegisterUserDto){

        const existUser = await UserModel.findOne({email: registerUserDto.email})

        if( existUser )  throw CustomError.badRequest('Email alredy exists');

        try{
            const user = new UserModel( registerUserDto );
            
            //Encriptar la contraseña
            user.password = bcryptAdapter.hash(registerUserDto.password);
            
            await user.save();

            await this.sendEmailValidationLink(user.email);

            const { password, ...userEntity } = UserEntity.fromObject(user);

            const token = await JwtAdapter.generateToken({id: user.id});
            if( !token )throw CustomError.internalServer('Error while creating JWT');


            return { 
                user: userEntity,
                token: token,
            };

        } catch (error) {
            throw CustomError.internalServer(`${error}`)
        }
    }

    public async loginUser(loginUserDto: LoginUserDto){
    

        const user = await UserModel.findOne({email: loginUserDto.email});
        if( !user )  throw CustomError.badRequest('Email not exist');
      
        const isMatch = bcryptAdapter.compare(loginUserDto.password, user.password);
        if( !isMatch ) throw CustomError.badRequest('Password is not valid');

        const { password, ...userEntity } = UserEntity.fromObject(user);

        const token = await JwtAdapter.generateToken({id: user.id});
        if( !token )throw CustomError.internalServer('Error while creating JWT');

        return {
            user: userEntity,
            token: token,
        }
    }

    private sendEmailValidationLink = async( email: string ) => {

        const token = await JwtAdapter.generateToken({email});
        if( !token ) throw CustomError.internalServer('Error getting token');

        const link = `${envs.WEBSERVICE_URL}/auth/validate-email/${token}`;

        const html = `
        <h1>Validate your email</h1>
        <p>Click on the following link to validate your email</p>
        <a href=${link}>Validate Here</a>
        `;

        const options = {
            to: email,
            subject: 'Validate yout email',
            htmlBody: html,
        
        }

        const isSet = await this.emailService.sendEmail(options);
        if(!isSet) throw CustomError.internalServer('Error sending email')

        return true;
    }

    public validateEmail = async( token: string) => {

        const payload = await JwtAdapter.validateToken(token);
        if(!payload) throw CustomError.unauthorized('Invalid token');

        const { email } = payload as { email: string };
        if( !email ) throw CustomError.internalServer('Email not in token')

        const user = await UserModel.findOne({email});
        if( !user ) throw CustomError.internalServer('Email not exists');

        user.emailValidated = true;
        await user.save();

        return true;

    }

}