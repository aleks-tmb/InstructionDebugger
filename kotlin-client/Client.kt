import java.io.PrintWriter
import java.net.Socket
import java.util.Scanner

const val END = "END"

fun main(args: Array<String>) {
    if (args.size != 2) {
        println("Usage: Client <hostname> <port>")
        return
    }

    val hostname = args[0]
    val port = args[1].toInt()

    try {
        Socket(hostname, port).use { socket ->
            val input = Scanner(System.`in`)
            val output = PrintWriter(socket.getOutputStream(), true)
            val reader = Scanner(socket.getInputStream())

            println("Connected to server at $hostname:$port")
            println("Enter commands (type 'exit' to quit):")

            // Read commands from input and send them to the server
            while (true) {
                print("> ")
                val command = input.nextLine()
                output.println(command + END)

                if (command.equals("exit", ignoreCase = true)) {
                    break
                }

                // Read server response until we encounter the END delimiter
                val responseBuilder = StringBuilder()
                // Use the Scanner without line-based delimiters
                reader.useDelimiter("")
  
                while (reader.hasNext()) {             
                    responseBuilder.append(reader.next())
                    // Check if the response contains the END delimiter
                    if (responseBuilder.contains(END)) {
                        // Remove the END delimiter if needed
                        val response = responseBuilder.removeSuffix(END).toString()
                        println("$response")
                        break
                    }
                }
            }

            println("Connection closed.")
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
}