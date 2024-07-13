#Lab6: Use the Requests package, haslib module
import hashlib
import requests
import subprocess
import os

def main():

    # Get the expected SHA-256 hash value of the VLC installer
    print("Va a funcion get_expected_sha256\n")
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    print("Va a funcion download_installer\n")
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)
    else:
        print("Installer no OK")


def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    # Hint: See example code in lab instructions entitled "Extracting Text from a Response Message Body"
    # Hint: Use str class methods, str slicing, and/or regex to extract the expected SHA-256 value from the text 
    
    #Send GET message to download the file
    file_url ='https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'
    resp_msg = requests.get(file_url)
  
    #Check whether the dowload was successful
    if resp_msg.status_code== requests.codes.ok:
          #Extract binary file content from response message body
          file_content=resp_msg.content
          
          #Calculate SHA-256 hast value
          image_hash = hashlib.sha256(file_content).hexdigest()
          
          #Print the hash value
          print(f"The value hash:\n")
          print(image_hash)   
    else:
        print("Step 1 No Ok, NO calculate SHA-256\n")       
    return 

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # TODO: Step 2
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    
    #Send GET message to download the file
    file_url ='https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'
    resp_msg = requests.get(file_url)
    
    #Check whether the download was successful
    if resp_msg.status_code == requests.codes.ok:
        #Extract binary file content from response message
        file_content = resp_msg.content
        return(file_content)
    else:
        print("Step 2 No Ok, NO download ok\n")    
    return

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
    # Hint: See example code in lab instructions entitled "Computing the Hash Value of a Response Message Body"
    
    #Send GET message to download the file
    file_url ='https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'
    resp_msg = requests.get(file_url)
    
    #Check whether the download was successful
    if resp_msg.status_code == requests.codes.ok:
        #Extract binary file content from response message body
        file_content = resp_msg.content
          
        #Calculate SHA-256 hast value
        image_hash = hashlib.sha256(file_content).hexdigest()
          
        #Print the hash value
        print(image_hash)   
        return(True)      
    else:
        print("Step 3, No Ok")
        return(False) 
    

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    
    #Send GET message to download the file
    file_url ='https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'
    resp_msg = requests.get(file_url)
    
    #Check whether the download was successful
    if resp_msg.status_code == requests.codes.ok:
        #Extract binary file content from response message
        file_content = resp_msg.content
        
        #Save the binary file content from response message
        with open(r'c:\Temp\vlc-3.0.17.4-win64.exe','wb') as file:
            file.write(file_content) 
    else:
        print("Step 4, Installer No Ok")   
    return

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    
    installer_path=r'c:\Temp\vlc-3.0.17.4-win64.exe'
    subprocess.run([installer_path,'/L=1033','/S'])
    return
 
    
def delete_installer(installer_path):
    # TODO: Step 6
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    installer_path=r'c:\pictures\vlc-3.0.17.4-win64.exe'
    os.remove(installer_path)
   
    return

if __name__ == '__main__':
    main()