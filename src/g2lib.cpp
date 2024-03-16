
#include <assert.h>
#include <time.h>
#include "timex.h"
#include "common_defs.h"
#include "string_helper.h"

#include "g2lib.h"
#include "g2_grid.h"
#include "g2_textbox.h"


using namespace glib;

// Global singleton
glib::g2Lib  glib::g2;

void g2Lib::LoadSpec ( std::string fname )
{
    std::string fpath;

    if ( !getFileLocation ( fname, fpath ) ) {
        printf ( "ERROR: Unable to find file %s\n", fname.c_str() );
        exit(-1);
    }
    char filepath[1024];
    strncpy ( filepath, fpath.c_str(), 1024 );
    
    FILE* fp = fopen ( filepath, "rt" );
    if ( fp==0x0 ) {
        printf ( "ERROR: Unable to open file %s\n", fname.c_str() );
        exit(-1);
    }
    char buf[2048];
    std::string lin, word;    

    // 1. load spec
    //
    while (fgets( buf, 2048, fp)) {        
        lin = strTrim(buf) + "|";       // strip '\n' and add |
        if ( lin.at(0)=='#' )           // skip comments
          continue;

        AddSpec ( lin );
    }
    fclose(fp);

    // 2. parse spec
    //
    for (int n=0; n < m_spec.size(); n++) {
        ParseSpecToDef ( m_spec[n] );       
    }    
    m_spec.clear();

    // 3. expand spec
    //
    // convert tables to sections
    bool is_table;
    std::vector<std::string> words;
    std::string table_secs, table_wids;
    std::string name, item, label, entry;
    for (int n=0; n < m_objdefs.size(); n++) {
        // get object def
        name = m_objdefs[n].name;        
        is_table = hasVal ( name, "opt", "table" );        

        if (is_table) {          
          // retrieve list of table items
          std::vector<std::string> itemlist;
          if ( getValList ( name, "item", itemlist ) > 0 ) {            
            
            // build table items
            float pct = 100.0 / itemlist.size();
            table_secs = "";
            table_wids = "";
            for (int j=0; j < itemlist.size(); j++) {
              getWords ( itemlist[j], words );
              item = words[0]+":item";
              label = words[0]+":label";
              entry = words[0];
              table_secs = table_secs + " | " + item;
              table_wids = table_wids + " | " + fToStr(pct)+"%";
              AddSpec ( item +" | is a | grid" );
              AddSpec ( item +" | has | X layout | 30% | 70%" );
              AddSpec ( item +" | has | sections | "+label+" | "+entry );
              AddSpec ( label +" | is a | item" );
              AddSpec ( label +" | has | text | "+entry );
            }
            // build table sections
            AddSpec ( name + " | has | sections " + table_secs );
            AddSpec ( name + " | has | Y layout " + table_wids );
            
          }
        }
    }
    // parse any new specs    
    for (int n=0; n < m_spec.size(); n++) {        
        ParseSpecToDef ( m_spec[n] );         
    }    
    m_spec.clear();

    // print object specs
    /*printf ( "---- SPEC\n" );
    for (int n=0; n < m_objdefs.size(); n++) {
        printf ( "%d: %s [%s]\n", n, m_objdefs[n].obj.c_str(), m_objdefs[n].isa.c_str() );
        for (int j=0; j < m_objdefs[n].keys.size(); j++) {
            printf ("  %s: %s\n", m_objdefs[n].keys[j].c_str(), m_objdefs[n].vals[j].c_str() );
        }
    }
    printf ( "----\n" ); */

    
}

void g2Lib::getWords ( std::string str, std::vector<std::string>& words, int maxw )
{
  // parse words into basic sentence
  std::string word;
  words.clear ();
  for (int n=0; str.length() > 0; n++) {
      word = strTrim( strSplitLeft ( str, "|" ) );
      if ( word.length() > 0 ) {
          if ( n <= maxw )
              words.push_back ( word );            
          else
              words[maxw] = words[maxw] + "|" + word;
      }
  }  
}

void g2Lib::AddSpec ( std::string lin ) 
{
  m_spec.push_back ( lin );
}

void g2Lib::ParseSpecToDef ( std::string lin ) 
{  
  std::vector<std::string> words;
  
  // convert spec to words
  getWords ( lin, words, 3 );
 
  // build object definition (not actual object)
  if (words.size() > 0 ) {

      // ensure there are 4
      while (words.size()<4)
          words.push_back ("X");
      
      // definition
      if (words[1].compare ( "is a")==0) {
          SetDef ( words[0], words[2] );
      } 
      if (words[1].compare ( "has")==0 || words[1].compare( "action")==0 ) {
          SetKeyVal ( words[0], words[2], words[3] );
      }
  }
}

void g2Lib::SetDef ( std::string name, std::string isa )
{
    g2Def* def = FindDef (name);
    if (!def) {
        g2Def newdef;
        newdef.name = name;
        newdef.isa = isa;
        m_objdefs.push_back ( newdef );
    }
} 

void g2Lib::SetKeyVal ( std::string name, std::string key, std::string val )
{
    g2Def* def = FindDef (name);
    if (def) {
        def->keys.push_back ( key );
        def->vals.push_back ( val );
        // dbgprintf ( "%s: %s %s\n", name.c_str(), key.c_str(), val.c_str() );
    } else {
        printf ("ERROR: %s not defined yet.\n", name.c_str() );
    }
}

std::string g2Lib::getVal ( std::string name, std::string key )
{
    g2Def* def = FindDef(name);
    if (def) {
        for (int j=0; j < def->keys.size(); j++) {
            if ( def->keys[j].compare( key ) == 0)
                return def->vals[j];
        }        
    }
    return "";  // not found
}

int g2Lib::getValList ( std::string name, std::string key, std::vector<std::string>& list )
{
    int cnt = 0;
    g2Def* def = FindDef(name);
    if (def) {      
        for (int j=0; j < def->keys.size(); j++) {
            if ( def->keys[j].compare( key ) == 0) {
              list.push_back ( def->vals[j] );
              cnt++;
            }              
        }        
    }
    return cnt;  
}

bool g2Lib::hasVal ( std::string name, std::string key, std::string val )
{
    g2Def* def = FindDef(name);
    if (def) {
        for (int j=0; j < def->keys.size(); j++) {
            if ( def->keys[j].compare( key ) == 0)
              if ( def->vals[j].compare( val ) ==0)
                return true;    // key has the val queried
        }        
    }
    return false;  
}

g2Def* g2Lib::FindDef ( std::string name )
{
    for (int n=0; n < m_objdefs.size(); n++) {
        if ( m_objdefs[n].name.compare (name)==0) {
            return &m_objdefs[n];
        }
    }
    // not found
    return 0x0;
}

uchar g2Lib::FindType ( std::string isa )
{
    if ( isa.compare("grid")==0) return 'g';
    if ( isa.compare("item")==0) return 'i';
    if ( isa.compare("table")==0) return 't';
    if ( isa.compare("page")==0) return 'p';    
    return '?';
}

g2Obj* g2Lib::FindObj ( std::string name )
{
    for (int n=0; n < m_objlist.size(); n++) {
        if ( m_objlist[n]->getName().compare (name)==0) {
            return m_objlist[n];
        }
    }
    // not found
    return 0x0;
}

g2Obj* g2Lib::AddObj ( std::string name, uchar typ )
{
    g2Obj* obj;
    // create object
    switch (typ) {
    case 'g': obj = new g2Grid; break;
    case 'i': obj = new g2TextBox; break;    
    default:
        return 0x0;
    };   
    obj->m_id = m_objlist.size();
    obj->m_name = name;

    // add to master list
    m_objlist.push_back ( obj );

    return obj;
}

void g2Lib::AddPage ( int id )
{
  std::string obj_name = m_objlist[ id ]->getName();

  m_pages.push_back ( id );

  bool is_startpage = hasVal ( obj_name, "opt", "start page" );
  bool is_active = hasVal ( obj_name, "opt", "active" );
  if ( is_active || is_startpage ) {
    OpenPage ( obj_name );    
  }
}

void g2Lib::OpenPage ( std::string name )
{
  g2Obj* obj = FindObj ( name );
  if ( obj !=0x0 ) {
    printf ( "opened: %s\n", name.c_str() );
    m_active_pages.push_back ( obj->m_id );
  }
}

          
void g2Lib::BuildAll ()
{
    std::string name, isa;
    uchar typ;
    g2Obj* obj;
    std::string cmd;

    // Pass 1 - build all objects first
    for (int n=0; n < m_objdefs.size(); n++) {

        // get name
        name = m_objdefs[n].name;        

        // get type
        isa = m_objdefs[n].isa;
        typ = FindType ( isa );
        if ( typ=='?' ) {
            printf ( "ERROR: Unknown object type %s for %s\n", isa.c_str(), name.c_str() );
            exit(-2);
        }        
        // add object        
        obj = AddObj ( name, typ );        
    }

    // Pass 2 - build layouts, sections and obj references
    uchar L;        
    bool is_page; 
    for (int n=0; n < m_objlist.size(); n++) {

        // get object
        obj = m_objlist[n];

        // check for pages        
        is_page = hasVal ( obj->getName(), "opt", "page" );
        if (is_page) {
            AddPage ( n );
        }               

        // apply layouts & sections for grids
        if ( obj->getType()=='g') { 

            if ( BuildLayout ( obj, G_LX ) ) { L = G_LX; }
            if ( BuildLayout ( obj, G_LY ) ) { L = G_LY; }

            BuildSections ( obj, L );            
        }        
    }
    
    // Pass 3 - apply item styling 
    std::string val ;
    for (int n=0; n < m_objlist.size(); n++) {
    
      // apply item styling
      obj = m_objlist[n];
      
      // find defintion      
      // - each definition provides a name, 'isa', and 'has' lists (multiple keys & vals) 

      g2Def* def = FindDef ( obj->getName() );   
      if ( def != 0x0 ) {
        for (int j=0; j < def->keys.size(); j++) {
          val = strTrim ( def->vals[j], "|" );        // do not split here (trim outer |)
          obj->SetProperty ( def->keys[j], val );    // O | has | K | V
        }
      }
    }

    // Start on first page    
    if ( m_pages.size()==0 ) {
      dbgprintf ( "ERROR: No pages specified. Must have at least one page.\n" );
    }
    if ( m_active_pages.size()==0 ) {
      dbgprintf ( "ERROR: Start page not specified. Mark a page as start page.\n" );
    }
}


bool g2Lib::BuildLayout ( g2Obj* obj, uchar ly )
{
    g2Obj tmp;
    uchar typ;
    float amt;
    g2Size size;
    std::string key, val, sz_str;
    g2Grid* grid = dynamic_cast<g2Grid*>( obj );    
    if (grid==0x0) {
        printf ("ERROR: This is not a grid.\n");
        exit(-2);
        return false;
    }
    
    // get the layout object we will build
    g2Layout* layout = grid->getLayout ( ly );
    if (layout==0x0) {
      printf ("ERROR: No layout found.\n");
      exit(-3);
    }

    // get layout spec from named definition
    switch ( ly ) {
    case G_LX: key = "X layout"; break;
    case G_LY: key = "Y layout"; break;
    };   
    val = getVal ( obj->getName(), key );   
    if ( val.size() == 0 ) {
      // no layout in this direction (only 1 axis can be active)
      return false;  
    }
    
    // active layout specifies the *size* of each section in a grid
    //    
    layout->active = true;

    for (int n=0; val.length()>0; n++) {

        sz_str = strSplitLeft ( val, "|" );
        
        size = tmp.ParseSize ( sz_str ) ;

        layout->sizes.push_back ( size );
    }

    return true;    
}

void g2Lib::BuildSections ( g2Obj* obj, uchar ly )
{
    g2Obj* obj_ref;
    std::string obj_name;
    std::string key, val, sz;
    g2Grid* grid = dynamic_cast<g2Grid*>( obj );   
    if (grid==0x0) {
        printf ("ERROR: This is not a grid.\n");
        exit(-2);
    }

    // get layout on object    
    g2Layout* layout = grid->getLayout ( ly );
     if (layout==0x0) {
      printf ("ERROR: No layout found.\n");
      exit(-3);
    }

    // get section spec from def
    val = getVal ( obj->getName(), "sections" );   

    if ( val.size() > 0 ) {

        // sections specify the *object* in each section of a grid
        //
        for (int n=0; val.length()>0; n++) {
            
            // find obj for this section
            obj_name = strSplitLeft ( val, "|" );            
            obj_ref = FindObj ( obj_name );

            if (obj_ref==0x0 && obj_name.compare(".") != 0) {
                // object not found, and is not a wildcard '.',
                // so lets create a placeholder for kindness
                obj_ref = AddObj ( obj_name, 'i' );                
            }           
            //printf ("%s (%p) ref by %s (%p)\n", obj_name.c_str(), obj_ref, obj->m_name.c_str(), obj );

            layout->sections.push_back ( obj_ref );
        }

    }
}

void g2Lib::LayoutAll (float xres, float yres)
{
    if ( m_objlist.size() == 0) { 
      dbgprintf ( "WARNING: g2 Layout has 0 objects.\n" );
      return; 
    }
    
    // layout all active pages
    //
    int id;
    for (int p=0; p < m_active_pages.size(); p++) {

      id = m_active_pages[ p ];      

      g2Obj* curr = m_objlist[ id ];
    
      curr->UpdateLayout ( Vec4F(0, 0, xres, yres) );

      //-- debugging
      /*int ow, oh;
      ow = curr->m_pos.z - curr->m_pos.x;
      oh = curr->m_pos.w - curr->m_pos.y;
      for (int n=0; n < m_objlist.size(); n++) {
        curr = m_objlist[n];
        dbgprintf ( "%s: %d x %d (%4.0f,%4.0f,%4.0f,%4.0f\n", curr->m_name.c_str(), ow, oh, curr->m_pos.x, curr->m_pos.y, curr->m_pos.z, curr->m_pos.w );
      }*/
    }
}


void g2Lib::Render (int w, int h)
{
    // dbgprintf ( "RENDER g2lib, %d %d\n", w, h);
    
    int id;
    
    // render all active pages 
    //
    for (int p=0; p < m_active_pages.size(); p++) {
    
      id = m_active_pages[p];    
    
      g2Obj* curr = m_objlist[ id ];

      start2D ( w, h );

      // setview2D ( curr->m_pos.z, curr->m_pos.w );

      curr->drawBackgrd ( curr->m_debug );     
      curr->drawForegrd ( curr->m_debug ); 
      curr->drawBorder  ( curr->m_debug ); 

      end2D();
    }
}
         
