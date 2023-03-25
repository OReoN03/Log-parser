package logparser;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Solution {
    public static void main(String[] args) {
        Date after = null;
        SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        try {
            after = formatter.parse("30.08.2012 16:08:40");
        }catch (ParseException ignored) {}

        Path logDir = Paths.get("C:\\Users\\Артем\\IdeaProjects\\LogParser");
        LogParser logParser = new LogParser(logDir);
        EnhancedLogParser enhancedLogParser = new EnhancedLogParser(logDir);

        System.out.println(enhancedLogParser.execute("get ip for user = \"Eduard Petrovich Morozko\" " +
                "and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));
        System.out.println(enhancedLogParser.execute("get ip for date = \"11.12.2013 10:11:12\" " +
                "and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));
        System.out.println(enhancedLogParser.execute("get ip for event = \"WRITE_MESSAGE\" " +
                "and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));
        System.out.println(enhancedLogParser.execute("get ip for status = \"FAILED\" " +
                "and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));
        System.out.println(enhancedLogParser.execute("get user for ip = \"146.34.15.5\" " +
                "and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));

    }
}