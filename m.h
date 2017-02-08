void read_postdata(struct toybufs **, struct mg_connection *conn);
void copy_postdata_to_mg(struct mg_connection *, struct toybufs *);
extern int sflag;
extern int vflag;
extern int Dflag;
extern pthread_key_t local_store;
