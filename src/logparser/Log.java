package logparser;

import java.util.Date;

public class Log {
    private String ip;
    private String user;
    private Date logDate;
    private Event event;
    private int task;
    private Status status;

    public Log(String ip, String user, Date logDate, Event event, int task, Status status) {
        this.ip = ip;
        this.user = user;
        this.logDate = logDate;
        this.event = event;
        this.task = task;
        this.status = status;
    }

    public String getIp() {
        return ip;
    }
    public String getUser() {
        return user;
    }
    public Date getLogDate() {
        return logDate;
    }
    public Event getEvent() {
        return event;
    }
    public int getTask() {
        return task;
    }
    public Status getStatus() {
        return status;
    }
}
