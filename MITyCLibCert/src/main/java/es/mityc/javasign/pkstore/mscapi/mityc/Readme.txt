Para generar la DLL del provider Sun MSCAPI con las modificaciones de MITyC se
requieren los siguientes elementos:

- Compilador de Visual C++ 2008. La versión Express es suficiente.
- Windows SDK.
- JDK 1.5, junto con una variable de entorno llamada JAVA_HOME_1_5 que apunte
  al directorio de instalación de dicho JDK

La DLL será generada tanto para 32 como para 64 bits.

------------------------------------
-- Generación de DLL para 32 bits --
------------------------------------
  
Los pasos para la generación de la DLL del provider Sun MSCAPI son los 
siguientes:

1. Arrancar el entorno de compilación de Microsoft, ejecutando el archivo 
"C:\Archivos de programa\Microsoft Visual Studio 9.0\VC\bin\Visual Studio 2008 Command Prompt",
que arrancará un prompt con el entorno de compilación de Visual C++ 2008 para 32 bits

2. Entrar en el directorio donde se encuentra el fichero security.cpp

3. Compilar
cl -c -Ox -I"%JAVA_HOME_1_5%\include" -I"%JAVA_HOME_1_5%\include\win32" /Fo..\..\..\..\..\..\..\build\security.obj security.cpp

4. Lincar
link -dll -release ..\..\..\..\..\..\..\build\security.obj "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\Crypt32.lib" "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\AdvAPI32.lib" -out:..\..\..\..\..\..\..\build\sunmscapi-mityc-i386.dll

Alternativamente, los pasos de compilación y lincado se pueden hacer en un solo comando:
cl -Ox -I"%JAVA_HOME_1_5%\include" -I"%JAVA_HOME_1_5%\include\win32" /Fo..\..\..\..\..\..\..\build\security.obj security.cpp -link -dll -release "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\Crypt32.lib" "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\AdvAPI32.lib" -manifestfile:manifest.xml -out:..\..\..\..\..\..\..\build\sunmscapi-mityc-i386.dll -version:1.0.0

------------------------------------
-- Generación de DLL para 64 bits --
------------------------------------

1. Arrancar el entorno de compilación de Microsoft, ejecutando el archivo 
"C:\Archivos de programa\Microsoft Visual Studio 9.0\VC\bin\Visual Studio 2008 x64 Cross Tools Command Prompt",
que arrancará un prompt con el entorno de compilación de Visual C++ 2008 para 64 bits

2. Entrar en el directorio donde se encuentra el fichero security.cpp

3. Compilar
cl -c -Ox -I"%JAVA_HOME_1_5%\include" -I"%JAVA_HOME_1_5%\include\win32" /Fo..\..\..\..\..\..\..\build\security.obj security.cpp

4. Lincar
link -dll -release security.obj "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\x64\Crypt32.lib" "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\x64\AdvAPI32.lib" -out:..\..\..\..\..\..\..\build\sunmscapi-mityc-x86_64.dll

Alternativamente, los pasos de compilación y lincado se pueden hacer en un solo comando:
cl -Ox -I"%JAVA_HOME_1_5%\include" -I"%JAVA_HOME_1_5%\include\win32" /Fo..\..\..\..\..\..\..\build\security.obj security.cpp -link -dll -release "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\x64\Crypt32.lib" "C:\Archivos de programa\Microsoft SDKs\Windows\v6.1\Lib\x64\AdvAPI32.lib" -out:..\..\..\..\..\..\..\build\sunmscapi-mityc-x86_64.dll -version:1.0.0
