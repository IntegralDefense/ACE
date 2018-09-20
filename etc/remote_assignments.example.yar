rule local : local
{
    strings:
        $ = "Received:"
    condition:
        any of them
}
