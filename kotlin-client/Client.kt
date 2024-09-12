import java.io.PrintWriter
import java.net.Socket
import java.util.Scanner
import kotlin.concurrent.thread
import kotlin.system.exitProcess

const val END = "END"
const val MAX_RETRY_ATTEMPTS = 10
const val RETRY_DELAY_MS = 3000L

fun main(args: Array<String>) {
    if (args.size != 2) {
        println("Usage: Client <hostname> <port>")
        return
    }

    val hostname = args[0]
    val port = args[1].toInt()

    var socket: Socket? = null
    var attempts = 0

    // Retry connection loop
    while (socket == null && attempts < MAX_RETRY_ATTEMPTS) {
        try {
            socket = Socket(hostname, port)
            println("Connected to server at $hostname:$port")
        } catch (e: Exception) {
            attempts++
            println("Failed to connect to $hostname:$port. Attempt $attempts of $MAX_RETRY_ATTEMPTS. Retrying in ${RETRY_DELAY_MS / 1000} seconds...")
            Thread.sleep(RETRY_DELAY_MS)
        }
    }

    // Exit if connection failed after max retries
    if (socket == null) {
        println("Could not connect to the server after $MAX_RETRY_ATTEMPTS attempts. Exiting...")
        exitProcess(1)
    }

    // Connection succeeded, proceed with normal operations
    try {
        socket.use { sock ->
            val input = Scanner(System.`in`)
            val output = PrintWriter(sock.getOutputStream(), true)
            val reader = Scanner(sock.getInputStream())

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
