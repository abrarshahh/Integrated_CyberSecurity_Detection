from django.http import HttpResponse
from django.shortcuts import render
import pickle

# Loading Saved Models
packet_model = pickle.load(open('models\\packet_detection.pkl','rb'))
url_model = pickle.load(open('models\\url_detection.pkl','rb'))
mail_model = pickle.load(open('models\\mail_detection.pkl','rb'))

# defining views for each page
def home(request):
    return render(request,"home.html")

def url_detection(request):
    return render(request, "url_detection.html")

def packet_detection(request):
    return render(request, "packet_detection.html")

def mail_detection(request):
    return render(request, "mail_detection.html")

# dynamic result page
def results(request):    
    # URL detection
    if 'url' in request.GET:
        url = request.GET['url']
        prediction = url_model.predict([url])
        message = "This url is "
        return render(request, "results.html", {'message': message, 'answer': prediction})
    
    # Email Detection
    elif 'email' in request.GET: 
        email = request.GET['email']
        prediction = mail_model.predict([email])
        message = 'This mail is '
        
        if  prediction == 0:
            prediction = "Ham"
            
        elif prediction == 1:
            prediction = "Spam"
        
        else:
            prediction = "Unknown"
        
        return render(request, "results.html", {'message': message, 'answer': prediction})
    
    # Traffic Packet Detection
    elif 'Source' in request.GET and 'Destination' in request.GET and 'Protocol' in request.GET and 'Length' in request.GET:    
        message = "This Traffic is "
        lis = []
            
        source = request.GET['Source']
        destination = request.GET['Destination'] 
        protocol = request.GET['Protocol']
        length = request.GET['Length']
    
        top_source_ips = ['192.167.5.35','192.232.16.204','192.167.5.22','142.251.32.14']
        top_dest_ips = ['192.167.5.22','192.167.5.35','192.232.16.204','Broadcast','192.167.255.255','142.251.32.14']
    
    
        # For Source Ips
        if source in top_source_ips:
            source = top_source_ips.index(source) + 1
        else:
            source = 5
    
        # For Destination Ips    
        if destination in top_dest_ips:
            destination = top_dest_ips.index(destination) + 1
        else:
            destination = 7
            
        # For Protocols
        if protocol == 'ARP':
            protocol = 1
        elif protocol == 'BROWSER':
            protocol = 2
        elif protocol == 'ICMP':
            protocol = 3
        elif protocol == 'NBNS':
            protocol = 4
        elif protocol == 'TCP':
            protocol = 5
        elif protocol == 'TLSv1.2':
            protocol = 6
        else:
            protocol = 7
            
                    
        # Adding to the list
        lis.append(source)
        lis.append(destination)
        lis.append(protocol)
        lis.append(length)
        
        #Model training
        prediction=packet_model.predict([lis])
        
        if prediction  == 0:
            prediction = 'Normal Traffic'
        elif prediction == 1:
            prediction = 'Malicious Traffic'
        
        return render(request, "results.html", {'message': message, 'answer': prediction})
    
    #Invalid options
    else:
        return HttpResponse("Invalid request")