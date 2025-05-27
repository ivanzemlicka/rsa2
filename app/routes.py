from flask import render_template, flash, url_for, redirect, request, abort #type: ignore
import secrets
import math
import app.decryption_rsa as decryption_rsa
import app.encryption_rsa as encryption_rsa
import app.blind_signature as blind_signature
import app.new_rsa as new_rsa
import random

from app import app

@app.route('/', methods=['GET', 'POST'])
def method():
    try:
        if request.method == 'POST':

        #home page

            if 'go_to_homepage' in request.form: #everywhere
                return render_template("main.html")

        #algorthms
        

            if "algorithms" in request.form:
                return render_template("algorithms.html")                

        #RSA principles
        

            if "RSA_principles" in request.form:
                return render_template("RSA_principles.html")                


        #encrypt

            elif "RSA_encrypt" in request.form: #homepage
                return render_template("RSA_encrypt.html")

            elif "this_RSA_encrypt" in request.form: #newrsa
                return render_template("RSA_encrypt.html",message_m="", n=(int(request.form.get("prime_p"))*int(request.form.get("prime_q"))),encryption_key_e=request.form.get("encryption_key_e"))        

            elif "encrypt_the_message" in request.form:
                m = int(request.form.get("enter_message_m"))
                encryption_key_e = int(request.form.get("enter_encryption_key_e"))
                n=int(request.form.get("enter_n"))
                em= encryption_rsa.Encrypt(m, encryption_key_e, n)
                return render_template("RSA_encrypted.html", message_m=m,encrypted_message_em=em)
            

        #decrypt

            elif "RSA_decrypt" in request.form: #homepage
                    return render_template("RSA_decrypt.html",prime_p="",prime_q="", message_m="",encryption_key_e="")
            
            elif "this_RSA_decrypt" in request.form: #newrsa
                return render_template("RSA_decrypt.html",prime_p=request.form.get("prime_p"),prime_q=request.form.get("prime_q"), message_m="",encryption_key_e=request.form.get("encryption_key_e"))

            elif "decrypt_the_message" in request.form: 
                p = int(request.form.get("enter_prime_p"))
                q=int(request.form.get("enter_prime_q"))
                encryption_key_e = int(request.form.get("enter_encryption_key_e"))
                em=int(request.form.get("enter_message_m"))
                if math.gcd(encryption_key_e,(p-1)*(q-1))!=1:
                    return render_template("error.html", error_text="e is badly choosed. It is not coprime with (p-1)(q-1) and therefore not invertible.")
                m= decryption_rsa.Decrypt_CRT(em, encryption_key_e, p, q)
                return render_template("RSA_decrypted.html", original_message=m,encrypted_message_em=em)

            elif "decrypt_the_encrypted_message_back" in request.form: #encrypted page
                m = int(request.form.get("enter_message_m"))
                encryption_key_e = int(request.form.get("enter_encryption_key_e"))
                n=int(request.form.get("enter_n"))
                em= encryption_rsa.Encrypt(m, encryption_key_e, n)
                return render_template("RSA_encrypted.html", message_m=m,encrypted_message_em=em)


        #new rsa

            elif "RSA_generate" in request.form: #homepage
                rsa=new_rsa.new_RSA(1024)
                p=rsa[0]
                q=rsa[1]
                n=rsa[2]
                phi_n=rsa[3]
                e=rsa[4]
                d=rsa[5]
                return render_template("generated_rsa.html",prime_p=p,prime_q=q,encryption_key_e=e)    
            

        #sign 
            elif "RSA_sign" in request.form: #homepage
                return render_template("sign.html") 
            
            elif "sign_the_blinded_message" in request.form: #blinded
                message_m=request.form.get("blinded_message")
                return render_template("sign.html",message_m=message_m) 
            
            elif "this_RSA_sign" in request.form: #newrsa
                return render_template("sign.html",prime_p=request.form.get("prime_p"),prime_q=request.form.get("prime_q"), message_m="",encryption_key_e=request.form.get("encryption_key_e"))
            elif "sign_the_message" in request.form:
                p = int(request.form.get("enter_prime_p"))
                q=int(request.form.get("enter_prime_q"))
                encryption_key_e = int(request.form.get("enter_encryption_key_e"))
                em=int(request.form.get("enter_message_m"))
                if math.gcd(encryption_key_e,(p-1)*(q-1))!=1:
                    return render_template("error.html", error_text="e is badly choosed. It is not coprime with (p-1)(q-1) and therefore not invertible.")
                m= decryption_rsa.Decrypt_CRT(em, encryption_key_e, p, q)
                return render_template("RSA_signed.html", original_message=m,encrypted_message_em=em,encryption_key_e=encryption_key_e,n=p*q)

            

            
        #authenticate        
            elif "RSA_authenticate_signature" in request.form: #homepage
                    return render_template("authenticate.html")
            elif "this_RSA_authenticate" in request.form: #newrsa
                return render_template("authenticate.html", n=int(request.form.get("prime_p"))*int(request.form.get("prime_q")), signed_message_sm="", message_m="",encryption_key_e=request.form.get("encryption_key_e"))

            elif "authenticate_the_signature" in request.form:
                m = int(request.form.get("enter_original_message_m"))
                sm = int(request.form.get("enter_signed_message_sm"))
                encryption_key_e = int(request.form.get("enter_encryption_key_e"))
                n=int(request.form.get("enter_n"))
                em= encryption_rsa.Encrypt(sm, encryption_key_e, n)
                if em==m:
                    return render_template("result.html", result="ok")
                else:
                    return render_template("result.html", result="no")    

            elif "authenticate_the_signature_of_the_signed_message" in request.form: #signed
                return render_template("authenticate.html", n=int(request.form.get("n")), signed_message_sm=int(request.form.get("original_message")), message_m=int(request.form.get("encrypted_message_em")),encryption_key_e=request.form.get("encryption_key_e"))
            
            

        #save rsa

            elif "this_RSA_save" in request.form: #newrsa

                
                return render_template("result.html", result="The RSA has been saved")



        #send page

            elif "send_a_message" in request.form: #homepage
                return render_template("send_encrypted_message_submit.html", user="",encrypted_message_em="")

            elif "send_the_encrypted_message" in request.form: #encrypt
                encrypted_message_em=request.form.get("encrypted_message_em")
                return render_template("send_encrypted_message_submit.html", user="",encrypted_message_em=encrypted_message_em)
            
            elif "send_the_message_submit" in request.form:
                user=request.form.get("user")
                encrypted_message_em=request.form.get("encrypted_message_em")
                return render_template("sent.html", user=user,encrypted_message_em=encrypted_message_em)

        #blind page
            elif "this_RSA_blind" in request.form: #newrsa
                return render_template("blind_message.html",n=int(request.form.get("prime_p"))*int(request.form.get("prime_q")), random=43, encryption_key_e=request.form.get("encryption_key_e"))
            
            elif "blind_a_message" in request.form: #homepage
                return render_template("blind_message.html",random=43)


        #blinded page
            elif "blind_the_message" in request.form: #blind page
                message_m=int(request.form.get("enter_message_m"))
                random=int(request.form.get("random"))
                encryption_key_e=int(request.form.get("enter_encryption_key_e"))
                n=int(request.form.get("enter_n"))
                blinded_message=int(blind_signature.blind(random,encryption_key_e,n,message_m))
                return render_template("blinded_message.html", blinded_message=blinded_message, message_m=message_m)


        #unblind page
            elif "unblind_a_message" in request.form: #homepage
                return render_template("unblind_message.html")

            elif "unblind_the_signed_message" in request.form: #signed
                signed_message=request.form.get("encrypted_message_em")
                encryption_key_e=request.form.get("encryption_key_e")
                n=request.form.get("n")
                return render_template("unblind_message.html",signed_message=signed_message,n=n)

        #unblinded page
            elif "unblind_the_message" in request.form: #signed
                signed_message_m=int(request.form.get("signed_message_m"))
                random=int(request.form.get("random"))
                n=int(request.form.get("n"))
                original_message=blind_signature.unblind(random,n,signed_message_m)
                return render_template("unblinded_message.html",original_message=original_message, blinded_message=signed_message_m)
            

        #error handling 
            
            elif "previous_page" in request.form:
                    previous_page = request.referrer  # This holds the URL of the previous page
                    return redirect(previous_page)

            else:
                return render_template("error.html", error_text="this option does not have page yet")


        #at the begining    

        elif request.method == 'GET':
            return render_template("main.html")


        #nonsense
        else:
            return render_template("error.html", error_text="not get not post")
    except:
        return render_template("error.html", error_text="probably some of the field was left blank. Try it again.")
